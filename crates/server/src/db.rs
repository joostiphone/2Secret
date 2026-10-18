//! SQLite storage. The server stores only ciphertext, public keys and a slow
//! hash of each account's authentication key.

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension};
use twosecret_core::api::{ItemDto, VaultDto};
use twosecret_core::crypto::{EncString, EncryptedKeyset, KdfParams, WrappedKey};
use twosecret_core::profile::Role;

use crate::error::{ApiError, ApiResult};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
    id          TEXT PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    salt        TEXT NOT NULL,
    kdf         TEXT NOT NULL,
    auth_hash   TEXT NOT NULL,
    keyset      TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    account_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_name  TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_account ON sessions(account_id);
CREATE TABLE IF NOT EXISTS vaults (
    id         TEXT PRIMARY KEY,
    owner_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    meta       TEXT NOT NULL,
    revision   INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    key_rev    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS vault_members (
    vault_id    TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    role        TEXT NOT NULL,
    wrapped_key TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (vault_id, account_id)
);
CREATE INDEX IF NOT EXISTS members_account ON vault_members(account_id);
CREATE TABLE IF NOT EXISTS items (
    vault_id   TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    id         TEXT NOT NULL,
    revision   INTEGER NOT NULL,
    data       TEXT,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (vault_id, id)
);
CREATE INDEX IF NOT EXISTS items_revision ON items(vault_id, revision);
CREATE TABLE IF NOT EXISTS shares (
    id         TEXT PRIMARY KEY,
    owner_id   TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    label      TEXT NOT NULL,
    data       TEXT NOT NULL,
    proof      TEXT NOT NULL,
    password   INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    views_left INTEGER,
    wrong      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS shares_owner ON shares(owner_id);
CREATE INDEX IF NOT EXISTS shares_expiry ON shares(expires_at);
"#;

/// Shared database handle.
#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

/// A stored account.
#[derive(Clone, Debug)]
pub struct AccountRow {
    pub id: String,
    pub email: String,
    pub name: String,
    pub salt: String,
    pub kdf: KdfParams,
    pub auth_hash: String,
    pub keyset: EncryptedKeyset,
    pub public_key: String,
    pub created_at: i64,
}

#[derive(Clone, Debug)]
pub struct SessionRow {
    pub id: String,
    pub account_id: String,
    pub device_name: String,
    pub created_at: i64,
    pub last_used_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug)]
pub struct Membership {
    pub role: Role,
    pub owner_id: String,
}

fn role_from_str(s: &str) -> Role {
    Role::parse(s).unwrap_or(Role::Viewer)
}

fn json_col<T: serde::de::DeserializeOwned>(s: String) -> rusqlite::Result<T> {
    serde_json::from_str(&s)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
}

fn enc(s: &str) -> rusqlite::Result<EncString> {
    EncString::parse(s)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
}

impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> anyhow::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> anyhow::Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        // Added in 1.2: the generation of each vault's key.
        let has_key_rev: bool =
            conn.query_row("SELECT COUNT(*) FROM pragma_table_info('vaults') WHERE name = 'key_rev'", [], |r| {
                r.get::<_, i64>(0).map(|n| n > 0)
            })?;
        if !has_key_rev {
            conn.execute("ALTER TABLE vaults ADD COLUMN key_rev INTEGER NOT NULL DEFAULT 0", [])?;
        }
        // Added in 1.5: the encrypted profile photo.
        let has_avatar: bool =
            conn.query_row("SELECT COUNT(*) FROM pragma_table_info('accounts') WHERE name = 'avatar'", [], |r| {
                r.get::<_, i64>(0).map(|n| n > 0)
            })?;
        if !has_avatar {
            conn.execute("ALTER TABLE accounts ADD COLUMN avatar TEXT", [])?;
        }
        conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '1')", [])?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    /// Run a closure with the connection on the blocking thread pool.
    pub async fn run<T, F>(&self, f: F) -> ApiResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> ApiResult<T> + Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().map_err(|_| ApiError::internal("database lock poisoned"))?;
            f(&mut guard)
        })
        .await?
    }
}

// ---------------------------------------------------------------------------
// Query helpers (all take a connection or transaction)
// ---------------------------------------------------------------------------

pub fn get_meta(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional()
}

pub fn set_meta(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn map_account(r: &rusqlite::Row<'_>) -> rusqlite::Result<AccountRow> {
    Ok(AccountRow {
        id: r.get(0)?,
        email: r.get(1)?,
        name: r.get(2)?,
        salt: r.get(3)?,
        kdf: json_col(r.get(4)?)?,
        auth_hash: r.get(5)?,
        keyset: json_col(r.get(6)?)?,
        public_key: r.get(7)?,
        created_at: r.get(8)?,
    })
}

const ACCOUNT_COLS: &str = "id, email, name, salt, kdf, auth_hash, keyset, public_key, created_at";

pub fn account_by_email(conn: &Connection, email: &str) -> rusqlite::Result<Option<AccountRow>> {
    conn.query_row(&format!("SELECT {ACCOUNT_COLS} FROM accounts WHERE email = ?1"), [email], map_account).optional()
}

pub fn account_by_id(conn: &Connection, id: &str) -> rusqlite::Result<Option<AccountRow>> {
    conn.query_row(&format!("SELECT {ACCOUNT_COLS} FROM accounts WHERE id = ?1"), [id], map_account).optional()
}

/// An account's encrypted profile photo.
pub fn avatar(conn: &Connection, account_id: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT avatar FROM accounts WHERE id = ?1", [account_id], |r| r.get(0))
        .optional()
        .map(Option::flatten)
}

pub fn set_avatar(conn: &Connection, account_id: &str, avatar: Option<&str>, now: i64) -> rusqlite::Result<()> {
    conn.execute("UPDATE accounts SET avatar = ?1, updated_at = ?2 WHERE id = ?3", params![avatar, now, account_id])?;
    Ok(())
}

pub fn insert_account(conn: &Connection, a: &AccountRow, now: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO accounts (id, email, name, salt, kdf, auth_hash, keyset, public_key, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
        params![
            a.id,
            a.email,
            a.name,
            a.salt,
            serde_json::to_string(&a.kdf).expect("serializable"),
            a.auth_hash,
            serde_json::to_string(&a.keyset).expect("serializable"),
            a.public_key,
            now
        ],
    )?;
    Ok(())
}

pub fn count_accounts(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0))
}

/// Bytes taken by the vaults an account owns (items and vault metadata).
pub fn storage_used(conn: &Connection, account_id: &str) -> rusqlite::Result<u64> {
    let used: i64 = conn.query_row(
        "SELECT COALESCE((SELECT SUM(LENGTH(i.data)) FROM items i JOIN vaults v ON v.id = i.vault_id
                          WHERE v.owner_id = ?1), 0)
              + COALESCE((SELECT SUM(LENGTH(meta)) FROM vaults WHERE owner_id = ?1), 0)",
        [account_id],
        |r| r.get(0),
    )?;
    Ok(used.max(0) as u64)
}

pub fn owned_vaults(conn: &Connection, account_id: &str) -> rusqlite::Result<u64> {
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM vaults WHERE owner_id = ?1", [account_id], |r| r.get(0))?;
    Ok(n.max(0) as u64)
}

pub fn insert_session(
    conn: &Connection,
    id: &str,
    token_hash: &str,
    account_id: &str,
    device_name: &str,
    now: i64,
    expires_at: i64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO sessions (id, token_hash, account_id, device_name, created_at, last_used_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
        params![id, token_hash, account_id, device_name, now, expires_at],
    )?;
    Ok(())
}

pub fn session_by_token(conn: &Connection, token_hash: &str) -> rusqlite::Result<Option<SessionRow>> {
    conn.query_row(
        "SELECT id, account_id, device_name, created_at, last_used_at, expires_at FROM sessions WHERE token_hash = ?1",
        [token_hash],
        |r| {
            Ok(SessionRow {
                id: r.get(0)?,
                account_id: r.get(1)?,
                device_name: r.get(2)?,
                created_at: r.get(3)?,
                last_used_at: r.get(4)?,
                expires_at: r.get(5)?,
            })
        },
    )
    .optional()
}

pub fn sessions_for_account(conn: &Connection, account_id: &str) -> rusqlite::Result<Vec<SessionRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, account_id, device_name, created_at, last_used_at, expires_at FROM sessions
         WHERE account_id = ?1 ORDER BY last_used_at DESC",
    )?;
    let rows = stmt.query_map([account_id], |r| {
        Ok(SessionRow {
            id: r.get(0)?,
            account_id: r.get(1)?,
            device_name: r.get(2)?,
            created_at: r.get(3)?,
            last_used_at: r.get(4)?,
            expires_at: r.get(5)?,
        })
    })?;
    rows.collect()
}

pub fn vault_dto(conn: &Connection, vault_id: &str, account_id: &str) -> rusqlite::Result<Option<VaultDto>> {
    conn.query_row(
        "SELECT v.id, v.owner_id, m.role, v.meta, m.wrapped_key, v.revision, v.created_at,
                (SELECT COUNT(*) FROM vault_members x WHERE x.vault_id = v.id), v.key_rev
         FROM vaults v JOIN vault_members m ON m.vault_id = v.id
         WHERE v.id = ?1 AND m.account_id = ?2",
        params![vault_id, account_id],
        map_vault,
    )
    .optional()
}

fn map_vault(r: &rusqlite::Row<'_>) -> rusqlite::Result<VaultDto> {
    let role: String = r.get(2)?;
    let meta: String = r.get(3)?;
    let wrapped: String = r.get(4)?;
    let revision: i64 = r.get(5)?;
    let members: i64 = r.get(7)?;
    let key_rev: i64 = r.get(8)?;
    Ok(VaultDto {
        id: r.get(0)?,
        owner_id: r.get(1)?,
        role: role_from_str(&role),
        meta: enc(&meta)?,
        wrapped_key: json_col::<WrappedKey>(wrapped)?,
        revision: revision as u64,
        created_at: r.get(6)?,
        member_count: members as u32,
        key_rev: key_rev as u64,
    })
}

pub fn vaults_for_account(conn: &Connection, account_id: &str) -> rusqlite::Result<Vec<VaultDto>> {
    let mut stmt = conn.prepare(
        "SELECT v.id, v.owner_id, m.role, v.meta, m.wrapped_key, v.revision, v.created_at,
                (SELECT COUNT(*) FROM vault_members x WHERE x.vault_id = v.id), v.key_rev
         FROM vaults v JOIN vault_members m ON m.vault_id = v.id
         WHERE m.account_id = ?1 ORDER BY v.created_at",
    )?;
    let rows = stmt.query_map([account_id], map_vault)?;
    rows.collect()
}

/// The current generation of a vault's key.
pub fn key_rev(conn: &Connection, vault_id: &str) -> rusqlite::Result<u64> {
    conn.query_row("SELECT key_rev FROM vaults WHERE id = ?1", [vault_id], |r| r.get::<_, i64>(0)).map(|n| n as u64)
}

pub fn membership(conn: &Connection, vault_id: &str, account_id: &str) -> rusqlite::Result<Option<Membership>> {
    conn.query_row(
        "SELECT m.role, v.owner_id FROM vault_members m JOIN vaults v ON v.id = m.vault_id
         WHERE m.vault_id = ?1 AND m.account_id = ?2",
        params![vault_id, account_id],
        |r| {
            let role: String = r.get(0)?;
            Ok(Membership { role: role_from_str(&role), owner_id: r.get(1)? })
        },
    )
    .optional()
}

pub fn item(conn: &Connection, vault_id: &str, id: &str) -> rusqlite::Result<Option<ItemDto>> {
    conn.query_row(
        "SELECT id, vault_id, revision, data FROM items WHERE vault_id = ?1 AND id = ?2",
        params![vault_id, id],
        map_item,
    )
    .optional()
}

fn map_item(r: &rusqlite::Row<'_>) -> rusqlite::Result<ItemDto> {
    let revision: i64 = r.get(2)?;
    let data: Option<String> = r.get(3)?;
    Ok(ItemDto {
        id: r.get(0)?,
        vault_id: r.get(1)?,
        revision: revision as u64,
        data: data.map(|d| enc(&d)).transpose()?,
    })
}

pub fn items_since(conn: &Connection, vault_id: &str, since: u64) -> rusqlite::Result<Vec<ItemDto>> {
    let mut stmt = conn.prepare(
        "SELECT id, vault_id, revision, data FROM items WHERE vault_id = ?1 AND revision > ?2 ORDER BY revision",
    )?;
    let rows = stmt.query_map(params![vault_id, since as i64], map_item)?;
    rows.collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn databases_from_1_1_get_the_key_rev_column() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE accounts (id TEXT PRIMARY KEY);
             CREATE TABLE vaults (
                 id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, meta TEXT NOT NULL,
                 revision INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
             );
             INSERT INTO accounts VALUES ('a');
             INSERT INTO vaults VALUES ('v', 'a', 'm', 3, 1, 1);",
        )
        .unwrap();
        let db = Db::init(conn).unwrap();
        let conn = db.conn.lock().unwrap();
        assert_eq!(key_rev(&conn, "v").unwrap(), 0);
    }
}
