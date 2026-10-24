//! Share links (`twosecret_core::share`). The server keeps the encrypted
//! content and gives it out only to whoever proves to know its key (the
//! proof the sender stored), a limited number of times until it expires; too
//! many wrong proofs delete the link. It also serves the page that opens the
//! links (`/s/<id>`), which decrypts in the browser with the key from the
//! link's fragment: that key never reaches the server.

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::{params, OptionalExtension};
use twosecret_core::api::{CreateShareRequest, OpenShareRequest, OpenShareResponse, ShareDto, ShareInfo};
use twosecret_core::crypto::{constant_time_eq, sha256, EncString};
use twosecret_core::util::{b64url, now};

use crate::auth::Auth;
use crate::client_ip::ClientIp;
use crate::error::{ApiError, ApiResult};
use crate::AppState;

/// Largest encrypted content: an item's fields and notes, no attachments.
const MAX_DATA: usize = 512 * 1024;
const MAX_LABEL: usize = 4 * 1024;
/// Links one account may have at a time.
const MAX_SHARES: i64 = 200;
const MAX_DAYS: i64 = 30;
const MAX_VIEWS: u32 = 100;
/// Wrong proofs (passwords) before a link is deleted.
const MAX_WRONG: i64 = 10;

/// `/api/v1/shares…`
pub fn api() -> Router<AppState> {
    Router::new().route("/shares", get(list).post(create)).route("/shares/{id}", get(info).delete(revoke)).route(
        "/shares/{id}/open",
        axum::routing::post(open).layer(axum::extract::DefaultBodyLimit::max(crate::routes::PUBLIC_BODY_BYTES)),
    )
}

/// The page that opens links.
pub fn pages() -> Router<AppState> {
    Router::new().route("/s/share.js", get(script)).route("/s/{id}", get(page))
}

/// 16 random bytes, base64url.
fn valid_id(id: &str) -> ApiResult<()> {
    if id.len() == 22 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        Ok(())
    } else {
        Err(ApiError::not_found("this link does not exist (any more)"))
    }
}

/// A SHA-256 hash, base64url.
fn valid_proof(proof: &str) -> bool {
    proof.len() == 43 && proof.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Marks a stored proof hash (see [`stored_proof`]).
const PROOF_HASH_PREFIX: &str = "h1.";

/// What the database keeps of a proof: its SHA-256. The proof is what opens
/// a link, so a copy of the database must not hold it (it could use up a
/// link's views before its recipient opens it).
fn stored_proof(proof: &str) -> String {
    format!("{PROOF_HASH_PREFIX}{}", b64url(&sha256(proof.as_bytes())))
}

/// Does `proof` match what the database keeps for a link? Links made before
/// proofs were hashed hold the proof itself; they expire within `MAX_DAYS`.
fn proof_matches(stored: &str, proof: &str) -> bool {
    match stored.strip_prefix(PROOF_HASH_PREFIX) {
        Some(hash) => constant_time_eq(hash.as_bytes(), b64url(&sha256(proof.as_bytes())).as_bytes()),
        None => constant_time_eq(stored.as_bytes(), proof.as_bytes()),
    }
}

async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Json(req): Json<CreateShareRequest>,
) -> ApiResult<StatusCode> {
    valid_id(&req.id).map_err(|_| ApiError::bad_request("invalid id"))?;
    if !valid_proof(&req.proof) {
        return Err(ApiError::bad_request("invalid proof"));
    }
    if req.data.len() > MAX_DATA || req.data.is_empty() {
        return Err(ApiError::bad_request("the shared content is too large"));
    }
    if req.label.len() > MAX_LABEL {
        return Err(ApiError::bad_request("label too large"));
    }
    let created = now();
    if req.expires_at <= created || req.expires_at > created + MAX_DAYS * 86_400 {
        return Err(ApiError::bad_request(format!("a link expires within {MAX_DAYS} days")));
    }
    if req.max_views.is_some_and(|v| v == 0 || v > MAX_VIEWS) {
        return Err(ApiError::bad_request(format!("a link can be opened 1 to {MAX_VIEWS} times")));
    }
    state
        .db
        .run(move |c| {
            let tx = c.transaction()?;
            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM shares WHERE owner_id = ?1 AND expires_at >= ?2",
                params![auth.account_id, created],
                |r| r.get(0),
            )?;
            if count >= MAX_SHARES {
                return Err(ApiError::forbidden(format!("you can have {MAX_SHARES} links at a time")));
            }
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO shares (id, owner_id, label, data, proof, password, created_at, expires_at, views_left, wrong)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
                params![
                    req.id,
                    auth.account_id,
                    req.label.as_str(),
                    req.data,
                    stored_proof(&req.proof),
                    req.password,
                    created,
                    req.expires_at,
                    req.max_views
                ],
            )?;
            if inserted == 0 {
                return Err(ApiError::conflict("link id already in use"));
            }
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<ShareDto>>> {
    let shares = state
        .db
        .run(move |c| {
            let mut stmt = c.prepare(
                "SELECT id, label, created_at, expires_at, views_left, password FROM shares
                 WHERE owner_id = ?1 AND expires_at >= ?2 ORDER BY created_at DESC",
            )?;
            let rows = stmt.query_map(params![auth.account_id, now()], |r| {
                let label: String = r.get(1)?;
                Ok((r.get::<_, String>(0)?, label, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
            })?;
            let mut shares = Vec::new();
            for row in rows {
                let (id, label, created_at, expires_at, views_left, password) = row?;
                let Ok(label) = EncString::parse(&label) else { continue };
                shares.push(ShareDto { id, label, created_at, expires_at, views_left, password });
            }
            Ok(shares)
        })
        .await?;
    Ok(Json(shares))
}

async fn revoke(State(state): State<AppState>, auth: Auth, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let deleted = state
        .db
        .run(
            move |c| Ok(c.execute("DELETE FROM shares WHERE id = ?1 AND owner_id = ?2", params![id, auth.account_id])?),
        )
        .await?;
    if deleted == 0 {
        return Err(ApiError::not_found("link not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn info(State(state): State<AppState>, Path(id): Path<String>) -> ApiResult<Json<ShareInfo>> {
    valid_id(&id)?;
    let info = state
        .db
        .run(move |c| {
            Ok(c.query_row(
                "SELECT expires_at, views_left, password FROM shares WHERE id = ?1 AND expires_at >= ?2",
                params![id, now()],
                |r| Ok(ShareInfo { expires_at: r.get(0)?, views_left: r.get(1)?, password: r.get(2)? }),
            )
            .optional()?)
        })
        .await?;
    info.map(Json).ok_or_else(|| ApiError::not_found("this link does not exist (any more)"))
}

async fn open(
    State(state): State<AppState>,
    client: ClientIp,
    Path(id): Path<String>,
    Json(req): Json<OpenShareRequest>,
) -> ApiResult<Json<OpenShareResponse>> {
    valid_id(&id)?;
    let limiter_key = format!("share:{}", client.0);
    let at = now();
    if !state.share_limiter.allowed(&limiter_key, at) {
        return Err(ApiError::too_many_requests());
    }
    state.share_limiter.record_failure(&limiter_key, at);
    state
        .db
        .run(move |c| {
            let tx = c.transaction()?;
            let row = tx
                .query_row(
                    "SELECT data, proof, views_left, wrong FROM shares WHERE id = ?1 AND expires_at >= ?2",
                    params![id, at],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, Option<u32>>(2)?,
                            r.get::<_, i64>(3)?,
                        ))
                    },
                )
                .optional()?;
            let Some((data, proof, views_left, wrong)) = row else {
                return Err(ApiError::not_found("this link does not exist (any more)"));
            };
            if !proof_matches(&proof, &req.proof) {
                if wrong + 1 >= MAX_WRONG {
                    tx.execute("DELETE FROM shares WHERE id = ?1", [&id])?;
                } else {
                    tx.execute("UPDATE shares SET wrong = wrong + 1 WHERE id = ?1", [&id])?;
                }
                tx.commit()?;
                return Err(ApiError::forbidden("wrong password"));
            }
            let views_left = match views_left {
                Some(v) if v <= 1 => {
                    tx.execute("DELETE FROM shares WHERE id = ?1", [&id])?;
                    Some(0)
                }
                Some(v) => {
                    tx.execute("UPDATE shares SET views_left = ?1 WHERE id = ?2", params![v - 1, id])?;
                    Some(v - 1)
                }
                None => None,
            };
            tx.commit()?;
            Ok(Json(OpenShareResponse { data, views_left }))
        })
        .await
}

/// Expired links go (called every minute).
pub fn delete_expired(conn: &rusqlite::Connection) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM shares WHERE expires_at < ?1", [now()])
}

const PAGE: &str = include_str!("share.html");
const SCRIPT: &str = include_str!("share.js");

async fn page(Path(_id): Path<String>) -> impl IntoResponse {
    (
        [(header::HeaderName::from_static("x-robots-tag"), "noindex, nofollow")],
        Html(PAGE.replace("{logo}", &twosecret_core::brand::tile_svg(44))),
    )
}

async fn script() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], SCRIPT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_database_keeps_a_hash_of_the_proof() {
        let proof = b64url(&[7u8; 32]);
        assert!(valid_proof(&proof));
        let stored = stored_proof(&proof);
        assert!(stored.starts_with(PROOF_HASH_PREFIX) && !stored.contains(&proof));
        assert!(proof_matches(&stored, &proof));
        assert!(!proof_matches(&stored, &b64url(&[8u8; 32])));
        assert!(!proof_matches(&stored, &stored[PROOF_HASH_PREFIX.len()..]));
        // A link from before the proofs were hashed.
        assert!(proof_matches(&proof, &proof));
        assert!(!proof_matches(&proof, &b64url(&[8u8; 32])));
    }
}
