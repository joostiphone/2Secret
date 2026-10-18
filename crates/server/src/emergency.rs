//! Emergency access: an account trusts someone (another account on this
//! server) with read access to the vaults it owns, for when it cannot give
//! that access itself. The owner's devices seal the vault keys to the
//! contact's public keys in advance; this server holds them back until the
//! contact asks and the waiting period has passed without the owner denying
//! (or the owner approves sooner). The contact then becomes a viewer of those
//! vaults, like after sharing them. The server cannot read the keys it holds.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use rusqlite::{params, Connection, OptionalExtension};
use twosecret_core::api::{
    AddEmergencyContactRequest, AddEmergencyContactResponse, EmergencyContactDto, EmergencyKey, EmergencyKeyState,
    EmergencyKeysRequest, EmergencyOverview, EmergencyRevoked,
};
use twosecret_core::crypto::EncryptedKeyset;
use twosecret_core::profile::Role;
use twosecret_core::util::{new_id, now};

use crate::auth::Auth;
use crate::error::{ApiError, ApiResult};
use crate::routes::valid_id;
use crate::{db, AppState};

/// People one account can trust at a time.
const MAX_CONTACTS: i64 = 10;
/// Longest waiting period.
pub const MAX_WAIT_DAYS: u32 = 90;

/// `/api/v1/emergency…`
pub fn api() -> Router<AppState> {
    Router::new()
        .route("/emergency", get(overview).post(add))
        .route("/emergency/{id}", axum::routing::delete(remove))
        .route("/emergency/{id}/keys", put(set_keys))
        .route("/emergency/{id}/request", post(request))
        .route("/emergency/{id}/approve", post(approve))
        .route("/emergency/{id}/reject", post(reject))
        .route("/emergency/{id}/open", post(open))
}

/// An arrangement as stored.
struct Contact {
    grantor_id: String,
    grantee_id: String,
    wait_days: u32,
    requested_at: Option<i64>,
    approved_at: Option<i64>,
}

impl Contact {
    fn grants_at(&self) -> Option<i64> {
        let requested = self.requested_at?;
        let waited = requested + i64::from(self.wait_days) * 86_400;
        Some(self.approved_at.map_or(waited, |approved| approved.min(waited)))
    }

    fn granted(&self, at: i64) -> bool {
        self.grants_at().is_some_and(|t| at >= t)
    }
}

fn contact(conn: &Connection, id: &str) -> ApiResult<Contact> {
    conn.query_row(
        "SELECT grantor_id, grantee_id, wait_days, requested_at, approved_at FROM emergency_contacts WHERE id = ?1",
        [id],
        |r| {
            Ok(Contact {
                grantor_id: r.get(0)?,
                grantee_id: r.get(1)?,
                wait_days: r.get(2)?,
                requested_at: r.get(3)?,
                approved_at: r.get(4)?,
            })
        },
    )
    .optional()?
    .ok_or_else(|| ApiError::not_found("emergency contact not found"))
}

/// The arrangement `id` of which `account` is the trusting side.
fn as_grantor(conn: &Connection, id: &str, account: &str) -> ApiResult<Contact> {
    let c = contact(conn, id)?;
    if c.grantor_id != account {
        return Err(ApiError::not_found("emergency contact not found"));
    }
    Ok(c)
}

/// The arrangement `id` of which `account` is the trusted contact.
fn as_grantee(conn: &Connection, id: &str, account: &str) -> ApiResult<Contact> {
    let c = contact(conn, id)?;
    if c.grantee_id != account {
        return Err(ApiError::not_found("emergency contact not found"));
    }
    Ok(c)
}

/// The arrangements of `account` on one side (`grantor_id` or `grantee_id`),
/// with the person on the other side.
fn list(conn: &Connection, account: &str, grantor_side: bool, at: i64) -> ApiResult<Vec<EmergencyContactDto>> {
    let (mine, other) = if grantor_side { ("grantor_id", "grantee_id") } else { ("grantee_id", "grantor_id") };
    let mut stmt = conn.prepare(&format!(
        "SELECT e.id, a.id, a.email, a.name, a.public_key, a.keyset, e.wait_days, e.created_at, e.requested_at,
                e.approved_at, e.grantor_id, e.grantee_id,
                EXISTS (SELECT 1 FROM emergency_members m WHERE m.contact_id = e.id)
         FROM emergency_contacts e JOIN accounts a ON a.id = e.{other}
         WHERE e.{mine} = ?1 ORDER BY e.created_at"
    ))?;
    let rows = stmt.query_map([account], |r| {
        let keyset: String = r.get(5)?;
        let c = Contact {
            grantor_id: r.get(10)?,
            grantee_id: r.get(11)?,
            wait_days: r.get(6)?,
            requested_at: r.get(8)?,
            approved_at: r.get(9)?,
        };
        Ok(EmergencyContactDto {
            id: r.get(0)?,
            account_id: r.get(1)?,
            email: r.get(2)?,
            name: r.get(3)?,
            public_key: r.get(4)?,
            pq_public_key: serde_json::from_str::<EncryptedKeyset>(&keyset).ok().and_then(|k| k.pq_public_key),
            wait_days: c.wait_days,
            created_at: r.get(7)?,
            requested_at: c.requested_at,
            grants_at: c.grants_at(),
            granted: c.granted(at),
            opened: r.get(12)?,
            keys: vec![],
        })
    })?;
    let mut list = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    if grantor_side {
        let mut stmt = conn.prepare("SELECT vault_id, key_rev FROM emergency_keys WHERE contact_id = ?1")?;
        for c in &mut list {
            c.keys = stmt
                .query_map([&c.id], |r| {
                    Ok(EmergencyKeyState { vault_id: r.get(0)?, key_rev: r.get::<_, i64>(1)? as u64 })
                })?
                .collect::<rusqlite::Result<_>>()?;
        }
    }
    Ok(list)
}

async fn overview(State(state): State<AppState>, auth: Auth) -> ApiResult<Json<EmergencyOverview>> {
    let overview = state
        .db
        .run(move |c| {
            let at = now();
            Ok(EmergencyOverview {
                contacts: list(c, &auth.account_id, true, at)?,
                trusted_by: list(c, &auth.account_id, false, at)?,
            })
        })
        .await?;
    Ok(Json(overview))
}

/// Store vault keys sealed to the contact of arrangement `id`: only of vaults
/// the trusting account owns, and of their current generation. When the
/// contact already opened the vaults, a vault added later opens too.
fn store_keys(conn: &Connection, id: &str, c: &Contact, keys: &[EmergencyKey]) -> ApiResult<()> {
    for key in keys {
        valid_id(&key.vault_id)?;
        if !key.wrapped_key.is_sealed() {
            return Err(ApiError::bad_request("emergency keys must be sealed to the contact's public key"));
        }
        let owner = db::membership(conn, &key.vault_id, &c.grantor_id)?.is_some_and(|m| m.role == Role::Owner);
        if !owner {
            return Err(ApiError::forbidden("only the keys of vaults you own can be given"));
        }
        if db::key_rev(conn, &key.vault_id)? != key.key_rev {
            return Err(ApiError::conflict("the vault key was replaced; sync and try again"));
        }
        conn.execute(
            "INSERT INTO emergency_keys (contact_id, vault_id, key_rev, wrapped_key) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(contact_id, vault_id) DO UPDATE SET key_rev = excluded.key_rev, wrapped_key = excluded.wrapped_key",
            params![id, key.vault_id, key.key_rev as i64, serde_json::to_string(&key.wrapped_key)?],
        )?;
    }
    let opened: bool =
        conn.query_row("SELECT EXISTS (SELECT 1 FROM emergency_members WHERE contact_id = ?1)", [id], |r| r.get(0))?;
    if opened && c.granted(now()) {
        grant(conn, id, c)?;
    }
    Ok(())
}

/// Make the contact a viewer of every vault whose current key the server
/// holds for them (and of which they are not a member yet).
fn grant(conn: &Connection, id: &str, c: &Contact) -> ApiResult<usize> {
    let keys: Vec<(String, String)> = conn
        .prepare(
            "SELECT k.vault_id, k.wrapped_key FROM emergency_keys k JOIN vaults v ON v.id = k.vault_id
             WHERE k.contact_id = ?1 AND k.key_rev = v.key_rev AND v.owner_id = ?2",
        )?
        .query_map(params![id, c.grantor_id], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut added = 0;
    for (vault_id, wrapped_key) in keys {
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO vault_members (vault_id, account_id, role, wrapped_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![vault_id, c.grantee_id, Role::Viewer.id(), wrapped_key, now()],
        )?;
        if inserted > 0 {
            conn.execute(
                "INSERT OR IGNORE INTO emergency_members (contact_id, vault_id) VALUES (?1, ?2)",
                params![id, vault_id],
            )?;
            added += 1;
        }
    }
    Ok(added)
}

/// Take away what arrangement `id` gave: the vaults its contact became a
/// member of through it. Their owner replaces those vaults' keys.
fn ungrant(conn: &Connection, id: &str, c: &Contact) -> ApiResult<Vec<String>> {
    let vaults: Vec<String> = conn
        .prepare("SELECT vault_id FROM emergency_members WHERE contact_id = ?1")?
        .query_map([id], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for vault_id in &vaults {
        conn.execute(
            "DELETE FROM vault_members WHERE vault_id = ?1 AND account_id = ?2 AND role != ?3",
            params![vault_id, c.grantee_id, Role::Owner.id()],
        )?;
    }
    conn.execute("DELETE FROM emergency_members WHERE contact_id = ?1", [id])?;
    Ok(vaults)
}

async fn add(
    State(state): State<AppState>,
    auth: Auth,
    Json(req): Json<AddEmergencyContactRequest>,
) -> ApiResult<Json<AddEmergencyContactResponse>> {
    valid_id(&req.account_id)?;
    if req.wait_days == 0 || req.wait_days > MAX_WAIT_DAYS {
        return Err(ApiError::bad_request(format!("the waiting period is 1 to {MAX_WAIT_DAYS} days")));
    }
    if req.account_id == auth.account_id {
        return Err(ApiError::bad_request("you cannot be your own emergency contact"));
    }
    let id = new_id();
    let response = AddEmergencyContactResponse { id: id.clone() };
    state
        .db
        .run(move |conn| {
            let tx = conn.transaction()?;
            if db::account_by_id(&tx, &req.account_id)?.is_none() {
                return Err(ApiError::not_found("account not found"));
            }
            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM emergency_contacts WHERE grantor_id = ?1",
                [&auth.account_id],
                |r| r.get(0),
            )?;
            if count >= MAX_CONTACTS {
                return Err(ApiError::forbidden(format!("you can have {MAX_CONTACTS} emergency contacts")));
            }
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO emergency_contacts (id, grantor_id, grantee_id, wait_days, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, auth.account_id, req.account_id, req.wait_days, now()],
            )?;
            if inserted == 0 {
                return Err(ApiError::conflict("this person already is an emergency contact"));
            }
            let c = as_grantor(&tx, &id, &auth.account_id)?;
            store_keys(&tx, &id, &c, &req.keys)?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(Json(response))
}

async fn set_keys(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(req): Json<EmergencyKeysRequest>,
) -> ApiResult<StatusCode> {
    state
        .db
        .run(move |conn| {
            let tx = conn.transaction()?;
            let c = as_grantor(&tx, &id, &auth.account_id)?;
            store_keys(&tx, &id, &c, &req.keys)?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The contact asks for access; it is granted after the waiting period.
async fn request(State(state): State<AppState>, auth: Auth, Path(id): Path<String>) -> ApiResult<StatusCode> {
    state
        .db
        .run(move |conn| {
            as_grantee(conn, &id, &auth.account_id)?;
            conn.execute(
                "UPDATE emergency_contacts SET requested_at = ?1, approved_at = NULL WHERE id = ?2 AND requested_at IS NULL",
                params![now(), id],
            )?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The trusting side grants a request now.
async fn approve(State(state): State<AppState>, auth: Auth, Path(id): Path<String>) -> ApiResult<StatusCode> {
    state
        .db
        .run(move |conn| {
            let c = as_grantor(conn, &id, &auth.account_id)?;
            if c.requested_at.is_none() {
                return Err(ApiError::bad_request("there is no request to approve"));
            }
            conn.execute(
                "UPDATE emergency_contacts SET approved_at = ?1 WHERE id = ?2 AND approved_at IS NULL",
                params![now(), id],
            )?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The trusting side denies a request, or the contact withdraws it; access
/// that was granted ends.
async fn reject(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<EmergencyRevoked>> {
    let vault_ids = state
        .db
        .run(move |conn| {
            let tx = conn.transaction()?;
            let c = contact(&tx, &id)?;
            if c.grantor_id != auth.account_id && c.grantee_id != auth.account_id {
                return Err(ApiError::not_found("emergency contact not found"));
            }
            tx.execute("UPDATE emergency_contacts SET requested_at = NULL, approved_at = NULL WHERE id = ?1", [&id])?;
            let vaults = ungrant(&tx, &id, &c)?;
            tx.commit()?;
            Ok(vaults)
        })
        .await?;
    Ok(Json(EmergencyRevoked { vault_ids }))
}

/// The contact takes the access they were granted.
async fn open(State(state): State<AppState>, auth: Auth, Path(id): Path<String>) -> ApiResult<StatusCode> {
    state
        .db
        .run(move |conn| {
            let tx = conn.transaction()?;
            let c = as_grantee(&tx, &id, &auth.account_id)?;
            if !c.granted(now()) {
                return Err(ApiError::forbidden("access has not been granted (yet)"));
            }
            grant(&tx, &id, &c)?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Either side ends the arrangement; access that was granted ends.
async fn remove(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<EmergencyRevoked>> {
    let vault_ids = state
        .db
        .run(move |conn| {
            let tx = conn.transaction()?;
            let c = contact(&tx, &id)?;
            if c.grantor_id != auth.account_id && c.grantee_id != auth.account_id {
                return Err(ApiError::not_found("emergency contact not found"));
            }
            let vaults = ungrant(&tx, &id, &c)?;
            tx.execute("DELETE FROM emergency_contacts WHERE id = ?1", [&id])?;
            tx.commit()?;
            Ok(vaults)
        })
        .await?;
    Ok(Json(EmergencyRevoked { vault_ids }))
}

/// A membership given or taken away by hand is no longer the arrangement's.
pub fn forget_member(conn: &Connection, vault_id: &str, account_id: &str) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM emergency_members WHERE vault_id = ?1
         AND contact_id IN (SELECT id FROM emergency_contacts WHERE grantee_id = ?2)",
        params![vault_id, account_id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(requested_at: Option<i64>, approved_at: Option<i64>) -> Contact {
        Contact { grantor_id: "a".into(), grantee_id: "b".into(), wait_days: 2, requested_at, approved_at }
    }

    #[test]
    fn access_after_the_waiting_period() {
        assert_eq!(contact(None, None).grants_at(), None);
        assert!(!contact(None, None).granted(i64::MAX));
        let asked = contact(Some(1_000), None);
        assert_eq!(asked.grants_at(), Some(1_000 + 2 * 86_400));
        assert!(!asked.granted(1_000 + 2 * 86_400 - 1));
        assert!(asked.granted(1_000 + 2 * 86_400));
        // Approved: from then on.
        let approved = contact(Some(1_000), Some(5_000));
        assert_eq!(approved.grants_at(), Some(5_000));
        assert!(approved.granted(5_000));
        assert!(!approved.granted(4_999));
    }
}
