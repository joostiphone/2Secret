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
    /// Bytes this account's own vaults take on the server (only in
    /// `GET /account`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_used: Option<u64>,
    /// The server's storage limit per account, if it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_quota: Option<u64>,
    /// The profile photo, encrypted with the account key (servers from 1.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<EncString>,
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

/// `PUT /account/avatar`: set (or with `None` remove) the profile photo.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SetAvatarRequest {
    pub avatar: Option<EncString>,
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
    /// ML-KEM-768 public key (absent for accounts that have not published one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_public_key: Option<String>,
}

/// Publish the account's ML-KEM-768 public key (`PUT /account/pq-key`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SetPqKeyRequest {
    pub pq_public_key: String,
}

/// Replace the caller's own wrapped key for a vault (`PUT /vaults/{id}/key`);
/// only wrappings with the caller's account key are accepted.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SetVaultKeyRequest {
    pub wrapped_key: WrappedKey,
    /// Generation of the vault key being stored (see [`VaultDto::key_rev`]);
    /// refused when the key was replaced meanwhile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_rev: Option<u64>,
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
    /// Generation of the vault key `meta` is encrypted with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_rev: Option<u64>,
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
    /// Generation of the vault key: increased every time the key is replaced
    /// (after removing a member). Writes encrypted with an older generation
    /// are refused.
    #[serde(default)]
    pub key_rev: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemberDto {
    pub account_id: String,
    pub email: String,
    pub name: String,
    pub role: Role,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_public_key: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AddMemberRequest {
    pub account_id: String,
    pub role: Role,
    pub wrapped_key: WrappedKey,
    /// Generation of the vault key in `wrapped_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_rev: Option<u64>,
}

/// Replace a vault's key: new metadata, every item re-encrypted and the new
/// key wrapped for every member. The server applies it all or nothing, and
/// only if the vault's key generation, member list and item list still match.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RotateVaultKeyRequest {
    /// The key generation being replaced.
    pub key_rev: u64,
    pub meta: EncString,
    pub members: Vec<MemberKey>,
    pub items: Vec<RotatedItem>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemberKey {
    pub account_id: String,
    pub wrapped_key: WrappedKey,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RotatedItem {
    pub id: String,
    pub data: EncString,
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
    /// Generation of the vault key `changes` are encrypted with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_rev: Option<u64>,
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
    /// Changes that were not stored because the vault owner's storage limit
    /// is reached. The client keeps them and tries again later.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub over_quota: Vec<String>,
    /// Changes that were not applied because they were encrypted with a
    /// vault key that has been replaced. The client re-encrypts them with the
    /// new key and sends them again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale_key: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SyncResponse {
    /// Every vault the account can access.
    pub vaults: Vec<VaultDto>,
    pub results: Vec<VaultSyncResult>,
}
