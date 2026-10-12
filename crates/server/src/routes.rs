//! HTTP handlers of the `/api/v1` API.

use std::collections::HashSet;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use rusqlite::params;
use serde::Deserialize;
use twosecret_core::api::*;
use twosecret_core::crypto::{hkdf32, EncryptedKeyset, KdfParams, PqPublicKey, PublicKey};
use twosecret_core::profile::Role;
use twosecret_core::util::{b64, normalize_email, now};

use crate::auth::{decode_auth_key, dummy_verify, hash_auth_key, new_token, verify_auth_key, Auth};
use crate::db::{self, AccountRow};
use crate::error::{ApiError, ApiResult};
use crate::{AppState, SignupMode};

pub fn api_router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/prelogin", post(prelogin))
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/account", get(get_account).put(update_account).delete(delete_account))
        .route("/account/password", post(change_password))
        .route("/account/pq-key", put(set_pq_key))
        .route("/devices", get(list_devices))
        .route("/devices/{id}", delete(revoke_device))
        .route("/users/lookup", get(lookup_user))
        .route("/vaults", get(list_vaults).post(create_vault))
        .route("/vaults/{id}", put(update_vault).delete(delete_vault))
        .route("/vaults/{id}/key", put(set_own_vault_key))
        .route("/vaults/{id}/rotate-key", post(rotate_vault_key))
        .route("/vaults/{id}/members", get(list_members).post(add_member))
        .route("/vaults/{id}/members/{account_id}", put(update_member).delete(remove_member))
        .route("/sync", post(sync))
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn valid_pq_key(key: Option<&str>) -> ApiResult<()> {
    match key {
        Some(k) => {
            PqPublicKey::from_b64(k).map(|_| ()).map_err(|_| ApiError::bad_request("invalid post-quantum public key"))
        }
        None => Ok(()),
    }
}

fn valid_id(id: &str) -> ApiResult<()> {
    let ok = !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad_request("invalid id"))
    }
}

fn valid_email(email: &str) -> ApiResult<String> {
    let e = normalize_email(email);
    let ok = e.len() <= 254
        && e.contains('@')
        && !e.starts_with('@')
        && !e.ends_with('@')
        && !e.chars().any(|c| c.is_whitespace() || c.is_control());
    if ok {
        Ok(e)
    } else {
        Err(ApiError::bad_request("invalid e-mail address"))
    }
}

fn valid_salt(salt: &str) -> ApiResult<()> {
    match twosecret_core::util::unb64(salt) {
        Ok(s) if (16..=64).contains(&s.len()) => Ok(()),
        _ => Err(ApiError::bad_request("invalid salt")),
    }
}

fn valid_kdf(kdf: &KdfParams) -> ApiResult<()> {
    kdf.validate().map_err(|e| ApiError::bad_request(e.to_string()))
}

fn device_name(name: Option<String>) -> String {
    let n: String = name.unwrap_or_default().chars().filter(|c| !c.is_control()).take(100).collect();
    if n.trim().is_empty() {
        "Unknown device".into()
    } else {
        n.trim().to_string()
    }
}

fn account_info(a: &AccountRow) -> AccountInfo {
    AccountInfo {
        account_id: a.id.clone(),
        email: a.email.clone(),
        name: a.name.clone(),
        salt: a.salt.clone(),
        kdf: a.kdf.clone(),
        keyset: a.keyset.clone(),
        created_at: a.created_at,
    }
}

// ---------------------------------------------------------------------------
// Public endpoints
// ---------------------------------------------------------------------------

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: twosecret_core::VERSION.into(),
        signups_open: state.config.signups != SignupMode::Closed,
        invite_required: state.config.signups == SignupMode::Invite,
    })
}

async fn prelogin(
    State(state): State<AppState>,
    Json(req): Json<PreloginRequest>,
) -> ApiResult<Json<PreloginResponse>> {
    let email = valid_email(&req.email)?;
    let lookup = email.clone();
    let account = state.db.run(move |c| Ok(db::account_by_email(c, &lookup)?)).await?;
    Ok(Json(match account {
        Some(a) => PreloginResponse { salt: a.salt, kdf: a.kdf },
        None => {
            // Stable fake answer so unknown addresses look like real ones.
            let fake = hkdf32(state.server_secret.as_bytes(), Some(email.as_bytes()), b"2secret-server/fake-prelogin");
            PreloginResponse { salt: b64(&fake.as_bytes()[..16]), kdf: KdfParams::default() }
        }
    }))
}

async fn register(State(state): State<AppState>, Json(req): Json<RegisterRequest>) -> ApiResult<Json<SessionResponse>> {
    match state.config.signups {
        SignupMode::Closed => return Err(ApiError::forbidden("sign-ups are closed on this server")),
        SignupMode::Invite => {
            let code = req.invite_code.as_deref().unwrap_or("").trim();
            if code.is_empty() || !state.config.invite_codes.iter().any(|c| c == code) {
                return Err(ApiError::forbidden("a valid invite code is required"));
            }
        }
        SignupMode::Open => {}
    }
    valid_id(&req.account_id)?;
    let email = valid_email(&req.email)?;
    valid_salt(&req.salt)?;
    valid_kdf(&req.kdf)?;
    let auth_key = decode_auth_key(&req.auth_key)?;
    PublicKey::from_b64(&req.keyset.public_key).map_err(|_| ApiError::bad_request("invalid public key"))?;
    valid_pq_key(req.keyset.pq_public_key.as_deref())?;
    let name: String = req.name.chars().filter(|c| !c.is_control()).take(100).collect();

    let auth_hash = tokio::task::spawn_blocking(move || hash_auth_key(&auth_key)).await??;
    let account = AccountRow {
        id: req.account_id.clone(),
        email,
        name,
        salt: req.salt.clone(),
        kdf: req.kdf.clone(),
        auth_hash,
        public_key: req.keyset.public_key.clone(),
        keyset: req.keyset.clone(),
        created_at: now(),
    };
    let session_days = state.config.session_days;
    let device = device_name(req.device_name);
    let (token, token_hash) = new_token();
    let info = state
        .db
        .run(move |conn| {
            let tx = conn.transaction()?;
            if db::account_by_email(&tx, &account.email)?.is_some() {
                return Err(ApiError::conflict("an account with this e-mail address already exists"));
            }
            if db::account_by_id(&tx, &account.id)?.is_some() {
                return Err(ApiError::conflict("account id already in use"));
            }
            let ts = now();
            db::insert_account(&tx, &account, ts)?;
            db::insert_session(
                &tx,
                &twosecret_core::util::new_id(),
                &token_hash,
                &account.id,
                &device,
                ts,
                ts + session_days * 86_400,
            )?;
            tx.commit()?;
            Ok(account_info(&account))
        })
        .await?;
    tracing::info!(account = %info.account_id, "account registered");
    Ok(Json(SessionResponse { token, account: info }))
}

async fn login(State(state): State<AppState>, Json(req): Json<LoginRequest>) -> ApiResult<Json<SessionResponse>> {
    let email = valid_email(&req.email)?;
    let auth_key = decode_auth_key(&req.auth_key)?;
    let limiter_key = format!("login:{email}");
    let ts = now();
    if !state.login_limiter.allowed(&limiter_key, ts) {
        return Err(ApiError::too_many_requests());
    }
    let lookup = email.clone();
    let account = state.db.run(move |c| Ok(db::account_by_email(c, &lookup)?)).await?;
    let verified = {
        let account = account.clone();
        tokio::task::spawn_blocking(move || match &account {
            Some(a) => verify_auth_key(&auth_key, &a.auth_hash),
            None => {
                dummy_verify(&auth_key);
                false
            }
        })
        .await?
    };
    let Some(account) = account.filter(|_| verified) else {
        state.login_limiter.record_failure(&limiter_key, ts);
        return Err(ApiError::invalid_credentials());
    };
    state.login_limiter.reset(&limiter_key);
    let (token, token_hash) = new_token();
    let session_days = state.config.session_days;
    let device = device_name(req.device_name);
    let account_id = account.id.clone();
    state
        .db
        .run(move |conn| {
            let ts = now();
            conn.execute("DELETE FROM sessions WHERE expires_at < ?1", [ts])?;
            db::insert_session(
                conn,
                &twosecret_core::util::new_id(),
                &token_hash,
                &account_id,
                &device,
                ts,
                ts + session_days * 86_400,
            )?;
            Ok(())
        })
        .await?;
    Ok(Json(SessionResponse { token, account: account_info(&account) }))
}

// ---------------------------------------------------------------------------
// Account
// ---------------------------------------------------------------------------

async fn logout(State(state): State<AppState>, auth: Auth) -> ApiResult<StatusCode> {
    state
        .db
        .run(move |c| {
            c.execute("DELETE FROM sessions WHERE id = ?1", [&auth.session_id])?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_account(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<AccountInfo>> {
    let account =
        state.db.run(move |c| db::account_by_id(c, &auth.account_id)?.ok_or_else(ApiError::unauthorized)).await?;
    Ok(Json(account_info(&account)))
}

async fn update_account(
    State(state): State<AppState>,
    auth: Auth,
    Json(req): Json<UpdateAccountRequest>,
) -> ApiResult<StatusCode> {
    let name: String = req.name.chars().filter(|c| !c.is_control()).take(100).collect();
    state
        .db
        .run(move |c| {
            c.execute(
                "UPDATE accounts SET name = ?1, updated_at = ?2 WHERE id = ?3",
                params![name.trim(), now(), auth.account_id],
            )?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn verify_current(state: &AppState, account_id: &str, auth_key_b64: &str) -> ApiResult<AccountRow> {
    let key = decode_auth_key(auth_key_b64)?;
    let id = account_id.to_string();
    let account = state.db.run(move |c| db::account_by_id(c, &id)?.ok_or_else(ApiError::unauthorized)).await?;
    let limiter_key = format!("verify:{}", account.id);
    if !state.login_limiter.allowed(&limiter_key, now()) {
        return Err(ApiError::too_many_requests());
    }
    let hash = account.auth_hash.clone();
    let ok = tokio::task::spawn_blocking(move || verify_auth_key(&key, &hash)).await?;
    if !ok {
        state.login_limiter.record_failure(&limiter_key, now());
        return Err(ApiError::invalid_credentials());
    }
    Ok(account)
}

async fn change_password(
    State(state): State<AppState>,
    auth: Auth,
    Json(req): Json<ChangePasswordRequest>,
) -> ApiResult<StatusCode> {
    verify_current(&state, &auth.account_id, &req.current_auth_key).await?;
    valid_salt(&req.salt)?;
    valid_kdf(&req.kdf)?;
    valid_pq_key(req.keyset.pq_public_key.as_deref())?;
    let new_key = decode_auth_key(&req.new_auth_key)?;
    let auth_hash = tokio::task::spawn_blocking(move || hash_auth_key(&new_key)).await??;
    let mut new_ks = req.keyset.clone();
    let kdf = serde_json::to_string(&req.kdf)?;
    state
        .db
        .run(move |c| {
            let tx = c.transaction()?;
            let (current_pk, current_ks): (String, String) =
                tx.query_row("SELECT public_key, keyset FROM accounts WHERE id = ?1", [&auth.account_id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
            if new_ks.public_key != current_pk {
                return Err(ApiError::bad_request("the keyset's public key cannot change"));
            }
            // Clients from before post-quantum sharing do not know the ML-KEM key: keep it.
            if new_ks.pq_public_key.is_none() {
                new_ks.pq_public_key = serde_json::from_str::<EncryptedKeyset>(&current_ks)?.pq_public_key;
            }
            let keyset = serde_json::to_string(&new_ks)?;
            tx.execute(
                "UPDATE accounts SET salt = ?1, kdf = ?2, auth_hash = ?3, keyset = ?4, updated_at = ?5 WHERE id = ?6",
                params![req.salt, kdf, auth_hash, keyset, now(), auth.account_id],
            )?;
            // Sign out every other device.
            tx.execute(
                "DELETE FROM sessions WHERE account_id = ?1 AND id != ?2",
                params![auth.account_id, auth.session_id],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_account(
    State(state): State<AppState>,
    auth: Auth,
    Json(req): Json<DeleteAccountRequest>,
) -> ApiResult<StatusCode> {
    verify_current(&state, &auth.account_id, &req.auth_key).await?;
    state
        .db
        .run(move |c| {
            let tx = c.transaction()?;
            // Owned vaults (and their items/memberships) go with the account.
            tx.execute("DELETE FROM vaults WHERE owner_id = ?1", [&auth.account_id])?;
            tx.execute("DELETE FROM accounts WHERE id = ?1", [&auth.account_id])?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    tracing::info!("account deleted");
    Ok(StatusCode::NO_CONTENT)
}

async fn list_devices(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<DeviceInfo>>> {
    let current = auth.session_id.clone();
    let sessions = state.db.run(move |c| Ok(db::sessions_for_account(c, &auth.account_id)?)).await?;
    Ok(Json(
        sessions
            .into_iter()
            .map(|s| DeviceInfo {
                current: s.id == current,
                id: s.id,
                name: s.device_name,
                created_at: s.created_at,
                last_used_at: s.last_used_at,
            })
            .collect(),
    ))
}

async fn revoke_device(State(state): State<AppState>, auth: Auth, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let n = state
        .db
        .run(move |c| {
            Ok(c.execute("DELETE FROM sessions WHERE id = ?1 AND account_id = ?2", params![id, auth.account_id])?)
        })
        .await?;
    if n == 0 {
        return Err(ApiError::not_found("device not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct LookupQuery {
    email: String,
}

async fn lookup_user(
    State(state): State<AppState>,
    _auth: Auth,
    Query(q): Query<LookupQuery>,
) -> ApiResult<Json<PublicKeyResponse>> {
    let email = valid_email(&q.email)?;
    let account = state
        .db
        .run(move |c| {
            db::account_by_email(c, &email)?
                .ok_or_else(|| ApiError::not_found("no 2Secret account with this e-mail address on this server"))
        })
        .await?;
    Ok(Json(PublicKeyResponse {
        account_id: account.id,
        email: account.email,
        name: account.name,
        public_key: account.public_key,
        pq_public_key: account.keyset.pq_public_key,
    }))
}

/// Publish the caller's ML-KEM-768 public key (post-quantum sharing).
async fn set_pq_key(
    State(state): State<AppState>,
    auth: Auth,
    Json(req): Json<SetPqKeyRequest>,
) -> ApiResult<StatusCode> {
    valid_pq_key(Some(&req.pq_public_key))?;
    state
        .db
        .run(move |c| {
            let tx = c.transaction()?;
            let keyset: String =
                tx.query_row("SELECT keyset FROM accounts WHERE id = ?1", [&auth.account_id], |r| r.get(0))?;
            let mut keyset: EncryptedKeyset = serde_json::from_str(&keyset)?;
            keyset.pq_public_key = Some(req.pq_public_key);
            tx.execute(
                "UPDATE accounts SET keyset = ?1, updated_at = ?2 WHERE id = ?3",
                params![serde_json::to_string(&keyset)?, now(), auth.account_id],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Vaults and sharing
// ---------------------------------------------------------------------------

async fn list_vaults(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<Vec<VaultDto>>> {
    Ok(Json(state.db.run(move |c| Ok(db::vaults_for_account(c, &auth.account_id)?)).await?))
}

async fn create_vault(
    State(state): State<AppState>,
    auth: Auth,
    Json(req): Json<CreateVaultRequest>,
) -> ApiResult<Json<VaultDto>> {
    valid_id(&req.id)?;
    if req.meta.len() > 64 * 1024 {
        return Err(ApiError::bad_request("vault metadata too large"));
    }
    let dto = state
        .db
        .run(move |c| {
            let tx = c.transaction()?;
            let exists: bool = tx
                .query_row("SELECT 1 FROM vaults WHERE id = ?1", [&req.id], |_| Ok(true))
                .unwrap_or(false);
            if exists {
                // Idempotent retry by the owner.
                if let Some(m) = db::membership(&tx, &req.id, &auth.account_id)? {
                    if m.role == Role::Owner {
                        return db::vault_dto(&tx, &req.id, &auth.account_id)?
                            .ok_or_else(|| ApiError::internal("vault vanished"));
                    }
                }
                return Err(ApiError::conflict("vault id already in use"));
            }
            let ts = now();
            tx.execute(
                "INSERT INTO vaults (id, owner_id, meta, revision, created_at, updated_at) VALUES (?1, ?2, ?3, 0, ?4, ?4)",
                params![req.id, auth.account_id, req.meta.as_str(), ts],
            )?;
            tx.execute(
                "INSERT INTO vault_members (vault_id, account_id, role, wrapped_key, created_at) VALUES (?1, ?2, 'owner', ?3, ?4)",
                params![req.id, auth.account_id, serde_json::to_string(&req.wrapped_key)?, ts],
            )?;
            let dto = db::vault_dto(&tx, &req.id, &auth.account_id)?.ok_or_else(|| ApiError::internal("vault vanished"))?;
            tx.commit()?;
            Ok(dto)
        })
        .await?;
    Ok(Json(dto))
}

fn require_role(conn: &rusqlite::Connection, vault_id: &str, account_id: &str, min: Role) -> ApiResult<db::Membership> {
    let m = db::membership(conn, vault_id, account_id)?.ok_or_else(|| ApiError::not_found("vault not found"))?;
    if m.role < min {
        return Err(ApiError::forbidden("insufficient permissions for this vault"));
    }
    Ok(m)
}

/// Writes that carry encrypted data must use the vault's current key.
/// Clients from before key rotation send no generation, which is fine until
/// the key is replaced for the first time.
fn require_key_rev(conn: &rusqlite::Connection, vault_id: &str, sent: Option<u64>) -> ApiResult<()> {
    if sent.unwrap_or(0) != db::key_rev(conn, vault_id)? {
        return Err(ApiError::conflict("the vault key was replaced; sync and try again"));
    }
    Ok(())
}

async fn update_vault(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(req): Json<UpdateVaultRequest>,
) -> ApiResult<StatusCode> {
    state
        .db
        .run(move |c| {
            require_role(c, &id, &auth.account_id, Role::Manager)?;
            require_key_rev(c, &id, req.key_rev)?;
            c.execute(
                "UPDATE vaults SET meta = ?1, updated_at = ?2 WHERE id = ?3",
                params![req.meta.as_str(), now(), id],
            )?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Owners delete the vault for everybody; other members leave it.
async fn delete_vault(State(state): State<AppState>, auth: Auth, Path(id): Path<String>) -> ApiResult<StatusCode> {
    state
        .db
        .run(move |c| {
            let m = require_role(c, &id, &auth.account_id, Role::Viewer)?;
            if m.owner_id == auth.account_id {
                c.execute("DELETE FROM vaults WHERE id = ?1", [&id])?;
            } else {
                c.execute(
                    "DELETE FROM vault_members WHERE vault_id = ?1 AND account_id = ?2",
                    params![id, auth.account_id],
                )?;
            }
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_members(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<MemberDto>>> {
    let members = state
        .db
        .run(move |c| {
            require_role(c, &id, &auth.account_id, Role::Viewer)?;
            let mut stmt = c.prepare(
                "SELECT a.id, a.email, a.name, m.role, a.public_key, a.keyset FROM vault_members m
                 JOIN accounts a ON a.id = m.account_id WHERE m.vault_id = ?1 ORDER BY m.created_at",
            )?;
            let rows = stmt.query_map([&id], |r| {
                let role: String = r.get(3)?;
                let keyset: String = r.get(5)?;
                Ok(MemberDto {
                    account_id: r.get(0)?,
                    email: r.get(1)?,
                    name: r.get(2)?,
                    role: Role::parse(&role).unwrap_or(Role::Viewer),
                    public_key: r.get(4)?,
                    pq_public_key: serde_json::from_str::<EncryptedKeyset>(&keyset).ok().and_then(|k| k.pq_public_key),
                })
            })?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await?;
    Ok(Json(members))
}

async fn add_member(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> ApiResult<StatusCode> {
    if req.role == Role::Owner {
        return Err(ApiError::bad_request("there can only be one owner"));
    }
    if !req.wrapped_key.is_sealed() {
        return Err(ApiError::bad_request("shared vault keys must be sealed to the member's public key"));
    }
    state
        .db
        .run(move |c| {
            require_role(c, &id, &auth.account_id, Role::Manager)?;
            require_key_rev(c, &id, req.key_rev)?;
            if db::account_by_id(c, &req.account_id)?.is_none() {
                return Err(ApiError::not_found("account not found"));
            }
            if let Some(existing) = db::membership(c, &id, &req.account_id)? {
                if existing.role == Role::Owner {
                    return Err(ApiError::bad_request("the owner already has access"));
                }
            }
            c.execute(
                "INSERT INTO vault_members (vault_id, account_id, role, wrapped_key, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(vault_id, account_id) DO UPDATE SET role = excluded.role, wrapped_key = excluded.wrapped_key",
                params![id, req.account_id, req.role.id(), serde_json::to_string(&req.wrapped_key)?, now()],
            )?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A member replaces their own wrapped vault key, e.g. a key that was sealed
/// to their public key is stored wrapped with their own account key instead.
async fn set_own_vault_key(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(req): Json<SetVaultKeyRequest>,
) -> ApiResult<StatusCode> {
    valid_id(&id)?;
    if req.wrapped_key.is_sealed() {
        return Err(ApiError::bad_request("a vault key can only be rewrapped with your own account key"));
    }
    state
        .db
        .run(move |c| {
            require_role(c, &id, &auth.account_id, Role::Viewer)?;
            require_key_rev(c, &id, req.key_rev)?;
            let updated = c.execute(
                "UPDATE vault_members SET wrapped_key = ?1 WHERE vault_id = ?2 AND account_id = ?3",
                params![serde_json::to_string(&req.wrapped_key)?, id, auth.account_id],
            )?;
            if updated == 0 {
                return Err(ApiError::not_found("vault not found"));
            }
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Replace a vault's key (after removing a member): new metadata, every item
/// re-encrypted and the new key for every member, all or nothing.
async fn rotate_vault_key(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(req): Json<RotateVaultKeyRequest>,
) -> ApiResult<StatusCode> {
    valid_id(&id)?;
    let max_item = state.config.max_item_bytes;
    if req.items.iter().any(|i| i.data.len() > max_item) {
        return Err(ApiError::bad_request("item too large"));
    }
    state
        .db
        .run(move |conn| {
            let tx = conn.transaction()?;
            require_role(&tx, &id, &auth.account_id, Role::Manager)?;
            if db::key_rev(&tx, &id)? != req.key_rev {
                return Err(ApiError::conflict("the vault key was replaced meanwhile; sync and try again"));
            }

            // The new key goes to every current member and nobody else.
            let members: HashSet<String> = tx
                .prepare("SELECT account_id FROM vault_members WHERE vault_id = ?1")?
                .query_map([&id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let sent: HashSet<String> = req.members.iter().map(|m| m.account_id.clone()).collect();
            if sent.len() != req.members.len() || sent != members {
                return Err(ApiError::conflict("the members of this vault changed; sync and try again"));
            }
            if req.members.iter().any(|m| m.account_id != auth.account_id && !m.wrapped_key.is_sealed()) {
                return Err(ApiError::bad_request("shared vault keys must be sealed to the member's public key"));
            }

            // Every item is re-encrypted, and nothing else.
            let items: HashSet<String> = tx
                .prepare("SELECT id FROM items WHERE vault_id = ?1 AND data IS NOT NULL")?
                .query_map([&id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let sent: HashSet<String> = req.items.iter().map(|i| i.id.clone()).collect();
            if sent.len() != req.items.len() || sent != items {
                return Err(ApiError::conflict("the items of this vault changed; sync and try again"));
            }

            let mut revision: i64 = tx.query_row("SELECT revision FROM vaults WHERE id = ?1", [&id], |r| r.get(0))?;
            let at = now();
            for item in &req.items {
                revision += 1;
                tx.execute(
                    "UPDATE items SET data = ?1, revision = ?2, updated_at = ?3 WHERE vault_id = ?4 AND id = ?5",
                    params![item.data.as_str(), revision, at, id, item.id],
                )?;
            }
            tx.execute(
                "UPDATE vaults SET meta = ?1, key_rev = key_rev + 1, revision = ?2, updated_at = ?3 WHERE id = ?4",
                params![req.meta.as_str(), revision, at, id],
            )?;
            for m in &req.members {
                tx.execute(
                    "UPDATE vault_members SET wrapped_key = ?1 WHERE vault_id = ?2 AND account_id = ?3",
                    params![serde_json::to_string(&m.wrapped_key)?, id, m.account_id],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn update_member(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, account_id)): Path<(String, String)>,
    Json(req): Json<UpdateMemberRequest>,
) -> ApiResult<StatusCode> {
    if req.role == Role::Owner {
        return Err(ApiError::bad_request("ownership cannot be transferred"));
    }
    state
        .db
        .run(move |c| {
            require_role(c, &id, &auth.account_id, Role::Manager)?;
            let target = db::membership(c, &id, &account_id)?.ok_or_else(|| ApiError::not_found("member not found"))?;
            if target.role == Role::Owner {
                return Err(ApiError::bad_request("the owner's role cannot be changed"));
            }
            c.execute(
                "UPDATE vault_members SET role = ?1 WHERE vault_id = ?2 AND account_id = ?3",
                params![req.role.id(), id, account_id],
            )?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_member(
    State(state): State<AppState>,
    auth: Auth,
    Path((id, account_id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    state
        .db
        .run(move |c| {
            if account_id != auth.account_id {
                require_role(c, &id, &auth.account_id, Role::Manager)?;
            }
            let target = db::membership(c, &id, &account_id)?.ok_or_else(|| ApiError::not_found("member not found"))?;
            if target.role == Role::Owner {
                return Err(ApiError::bad_request("the owner cannot be removed; delete the vault instead"));
            }
            c.execute("DELETE FROM vault_members WHERE vault_id = ?1 AND account_id = ?2", params![id, account_id])?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

async fn sync(
    State(state): State<AppState>,
    auth: Auth,
    Json(req): Json<SyncRequest>,
) -> ApiResult<Json<SyncResponse>> {
    let max_item = state.config.max_item_bytes;
    let response = state
        .db
        .run(move |conn| {
            let tx = conn.transaction()?;
            let accessible = db::vaults_for_account(&tx, &auth.account_id)?;
            let mut results = Vec::new();
            for vault in &accessible {
                let request = req.vaults.iter().find(|v| v.vault_id == vault.id);
                let since = request.map(|r| r.since).unwrap_or(0);
                let mut revision = vault.revision;
                let mut accepted = Vec::new();
                let mut conflicts = Vec::new();
                let mut rejected = Vec::new();
                let mut stale_key = Vec::new();
                if let Some(request) = request {
                    let current_key = request.key_rev.unwrap_or(0) == vault.key_rev;
                    let mut seen = HashSet::new();
                    for change in &request.changes {
                        if !seen.insert(change.id.clone()) {
                            continue;
                        }
                        if valid_id(&change.id).is_err()
                            || !vault.role.can_write()
                            || change.data.as_ref().is_some_and(|d| d.len() > max_item)
                        {
                            rejected.push(change.id.clone());
                            continue;
                        }
                        if change.data.is_some() && !current_key {
                            stale_key.push(change.id.clone());
                            continue;
                        }
                        let current = db::item(&tx, &vault.id, &change.id)?;
                        let current_rev = current.as_ref().map(|c| c.revision).unwrap_or(0);
                        if let Some(cur) = &current {
                            if change.base_revision != current_rev {
                                conflicts.push(cur.clone());
                                continue;
                            }
                        }
                        if current.is_none() && change.data.is_none() {
                            // Deleting something the server never had.
                            accepted.push(Accepted { id: change.id.clone(), revision });
                            continue;
                        }
                        revision += 1;
                        tx.execute(
                            "INSERT INTO items (vault_id, id, revision, data, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
                             ON CONFLICT(vault_id, id) DO UPDATE SET revision = excluded.revision,
                               data = excluded.data, updated_at = excluded.updated_at",
                            params![
                                vault.id,
                                change.id,
                                revision as i64,
                                change.data.as_ref().map(|d| d.as_str().to_string()),
                                now()
                            ],
                        )?;
                        accepted.push(Accepted { id: change.id.clone(), revision });
                    }
                    if revision != vault.revision {
                        tx.execute(
                            "UPDATE vaults SET revision = ?1, updated_at = ?2 WHERE id = ?3",
                            params![revision as i64, now(), vault.id],
                        )?;
                    }
                }
                let accepted_ids: HashSet<&str> = accepted.iter().map(|a| a.id.as_str()).collect();
                let changes = db::items_since(&tx, &vault.id, since)?
                    .into_iter()
                    .filter(|i| !accepted_ids.contains(i.id.as_str()))
                    .collect();
                results.push(VaultSyncResult {
                    vault_id: vault.id.clone(),
                    revision,
                    accepted,
                    conflicts,
                    changes,
                    rejected,
                    stale_key,
                });
            }
            let vaults = db::vaults_for_account(&tx, &auth.account_id)?;
            tx.commit()?;
            Ok(SyncResponse { vaults, results })
        })
        .await?;
    Ok(Json(response))
}
