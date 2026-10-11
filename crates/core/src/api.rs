//! Data transfer objects of the 2Secret sync API (`/api/v1`). Shared by the
//! server and all clients so both sides always agree on the wire format.
//!
//! The server only ever sees ciphertext ([`EncString`], [`WrappedKey`]),
//! public keys and the authentication key; never passwords, Secret Keys,
//! vault keys or item contents.

use serde::{Deserialize, Serialize};

use crate::crypto::{EncString, EncryptedKeyset, KdfParams, WrappedKey};
use crate::profile::Role;

pub const API_VERSION: &str = "v1";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub signups_open: bool,
    pub invite_required: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PreloginRequest {
    pub email: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PreloginResponse {
    pub salt: String,
    pub kdf: KdfParams,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub account_id: String,
    pub email: String,
    pub name: String,
    pub salt: String,
    pub kdf: KdfParams,
    /// Base64 authentication key (derived from password + Secret Key).
    pub auth_key: String,
    pub keyset: EncryptedKeyset,
    #[serde(default)]
    pub invite_code: Option<String>,
    #[serde(default)]
    pub device_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub auth_key: String,
    #[serde(default)]
    pub device_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountInfo {
    pub account_id: String,
    pub email: String,
    pub name: String,
    pub salt: String,
    pub kdf: KdfParams,
    pub keyset: EncryptedKeyset,
    pub created_at: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionResponse {
    pub token: String,
    pub account: AccountInfo,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_auth_key: String,
    pub new_auth_key: String,
    pub salt: String,
    pub kdf: KdfParams,
    pub keyset: EncryptedKeyset,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateAccountRequest {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeleteAccountRequest {
    pub auth_key: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: i64,
    pub current: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub account_id: String,
    pub email: String,
    pub name: String,
    pub public_key: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CreateVaultRequest {
    pub id: String,
    pub meta: EncString,
    pub wrapped_key: WrappedKey,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateVaultRequest {
    pub meta: EncString,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VaultDto {
    pub id: String,
    pub owner_id: String,
    pub role: Role,
    pub meta: EncString,
    pub wrapped_key: WrappedKey,
    pub revision: u64,
    pub member_count: u32,
    pub created_at: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemberDto {
    pub account_id: String,
    pub email: String,
    pub name: String,
    pub role: Role,
    pub public_key: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AddMemberRequest {
    pub account_id: String,
    pub role: Role,
    pub wrapped_key: WrappedKey,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UpdateMemberRequest {
    pub role: Role,
}

/// One item as stored on the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemDto {
    pub id: String,
    pub vault_id: String,
    pub revision: u64,
    /// `None` when the item was deleted.
    pub data: Option<EncString>,
}

/// A local change to upload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ItemChange {
    pub id: String,
    /// Server revision the change is based on (0 = new item).
    pub base_revision: u64,
    /// `None` deletes the item.
    pub data: Option<EncString>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VaultSyncRequest {
    pub vault_id: String,
    /// Return changes with a revision greater than this.
    pub since: u64,
    #[serde(default)]
    pub changes: Vec<ItemChange>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SyncRequest {
    pub vaults: Vec<VaultSyncRequest>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Accepted {
    pub id: String,
    pub revision: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VaultSyncResult {
    pub vault_id: String,
    /// Vault revision after applying this request.
    pub revision: u64,
    pub accepted: Vec<Accepted>,
    /// Current server versions of items whose `base_revision` was stale.
    pub conflicts: Vec<ItemDto>,
    /// Items changed by others since `since`.
    pub changes: Vec<ItemDto>,
    /// Changes that were refused (e.g. read-only access).
    #[serde(default)]
    pub rejected: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SyncResponse {
    /// Every vault the account can access.
    pub vaults: Vec<VaultDto>,
    pub results: Vec<VaultSyncResult>,
}
