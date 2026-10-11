//! High level account and sync operations shared by the CLI and all apps.

use std::collections::HashMap;

use twosecret_core::api::*;
use twosecret_core::crypto::{derive_keys, KdfParams, SecretKey};
use twosecret_core::profile::{AccountRecord, Role, ServerLink, SyncState};
use twosecret_core::session::Session;
use twosecret_core::sync::SyncReport;
use twosecret_core::util::{b64, unb64};
use twosecret_core::watchtower;

use crate::{normalize_server_url, Client, Error, Result};

/// A client for the server this session is linked to.
pub fn client_for(session: &Session) -> Result<Client> {
    let link = session.server().ok_or(Error::NotLinked)?;
    let token = session.server_token().ok_or(Error::Unauthorized)?;
    Ok(Client::new(&link.url).with_token(token))
}

/// Create a new account on a server. Returns the unlocked session and the
/// new Secret Key (show it to the user and offer the Emergency Kit!).
#[allow(clippy::too_many_arguments)]
pub async fn signup(
    server_url: &str,
    name: &str,
    email: &str,
    password: &str,
    invite_code: Option<&str>,
    device_name: &str,
    default_vault_name: &str,
    kdf: KdfParams,
) -> Result<(Session, SecretKey)> {
    let (mut session, secret_key) = Session::create_account(name, email, password, kdf, default_vault_name)?;
    connect(&mut session, server_url, password, &secret_key, invite_code, device_name).await?;
    Ok((session, secret_key))
}

/// Register an existing local account on a server and upload all vaults.
pub async fn connect(
    session: &mut Session,
    server_url: &str,
    password: &str,
    secret_key: &SecretKey,
    invite_code: Option<&str>,
    device_name: &str,
) -> Result<SyncReport> {
    let keys = session.verify_password(password, secret_key)?;
    let url = normalize_server_url(server_url);
    let client = Client::new(&url);
    let account = session.account().clone();
    let resp = client
        .register(&RegisterRequest {
            account_id: account.id.clone(),
            email: account.email.clone(),
            name: account.name.clone(),
            salt: account.salt.clone(),
            kdf: account.kdf.clone(),
            auth_key: b64(keys.auth_key.as_bytes()),
            keyset: account.keyset.clone(),
            invite_code: invite_code.map(|s| s.to_string()),
            device_name: Some(device_name.to_string()),
        })
        .await?;
    if session.server().is_some_and(|s| s.url != url) {
        session.unlink_server();
    }
    session.set_server(&url, &resp.token);
    sync(session).await
}

/// Sign in to an existing server account on a new device.
pub async fn signin(
    server_url: &str,
    email: &str,
    password: &str,
    secret_key: &SecretKey,
    device_name: &str,
) -> Result<Session> {
    let url = normalize_server_url(server_url);
    let client = Client::new(&url);
    let pre = client.prelogin(email).await?;
    pre.kdf.validate()?;
    let salt = unb64(&pre.salt)?;
    let keys = derive_keys(password, secret_key, email, &salt, &pre.kdf)?;
    let resp = client
        .login(&LoginRequest {
            email: email.to_string(),
            auth_key: b64(keys.auth_key.as_bytes()),
            device_name: Some(device_name.to_string()),
        })
        .await?;
    let info = resp.account;
    let account = AccountRecord {
        id: info.account_id,
        email: info.email,
        name: info.name,
        salt: info.salt,
        kdf: info.kdf,
        keyset: info.keyset,
        created_at: info.created_at,
    };
    let mut session = Session::from_server_account(
        account,
        &keys,
        ServerLink {
            url: url.clone(),
            token: None,
            last_sync_at: None,
        },
    )?;
    session.set_server(&url, &resp.token);
    sync(&mut session).await?;
    Ok(session)
}

/// Obtain a fresh token for a linked session (after it expired or was
/// revoked) using the master password.
pub async fn reauthenticate(session: &mut Session, password: &str, secret_key: &SecretKey, device_name: &str) -> Result<()> {
    let link = session.server().ok_or(Error::NotLinked)?.clone();
    let keys = session.verify_password(password, secret_key)?;
    let client = Client::new(&link.url);
    let resp = client
        .login(&LoginRequest {
            email: session.account().email.clone(),
            auth_key: b64(keys.auth_key.as_bytes()),
            device_name: Some(device_name.to_string()),
        })
        .await?;
    // Pick up a password changed on another device.
    let info = resp.account;
    if info.keyset != session.account().keyset {
        return Err(Error::Protocol(
            "the account keyset changed on the server; sign in again".into(),
        ));
    }
    session.set_server(&link.url, &resp.token);
    Ok(())
}

/// Synchronise all vaults with the server.
pub async fn sync(session: &mut Session) -> Result<SyncReport> {
    let client = client_for(session)?;

    for v in session.vaults_pending(SyncState::PendingCreate) {
        client
            .create_vault(&CreateVaultRequest {
                id: v.id.clone(),
                meta: v.meta.clone(),
                wrapped_key: v.wrapped_key.clone(),
            })
            .await?;
        session.mark_vault_synced(&v.id);
    }
    for v in session.vaults_pending(SyncState::PendingUpdate) {
        if v.role.can_manage() {
            match client.update_vault(&v.id, &UpdateVaultRequest { meta: v.meta.clone() }).await {
                Ok(()) => {}
                Err(e) if e.is_not_found() || e.status() == Some(403) => {}
                Err(e) => return Err(e),
            }
        }
        session.mark_vault_synced(&v.id);
    }
    for v in session.vaults_pending(SyncState::PendingDelete) {
        match client.delete_vault(&v.id).await {
            Ok(()) => {}
            Err(e) if e.is_not_found() => {}
            Err(e) => return Err(e),
        }
        session.forget_vault(&v.id);
    }

    let mut total = SyncReport::default();
    for _ in 0..5 {
        let req = session.sync_request();
        let resp = client.sync(&req).await?;
        let report = session.apply_sync_response(resp)?;
        total.merge(&report);
        let dirty = session.profile().items.iter().any(|i| {
            i.dirty
                && session
                    .profile()
                    .vault(&i.vault_id)
                    .is_some_and(|v| v.role.can_write())
        });
        if !report.needs_another_round && !dirty && report.vaults_added == 0 {
            break;
        }
    }
    total.needs_another_round = false;
    Ok(total)
}

/// Share a vault with another account on the same server.
pub async fn share_vault(session: &mut Session, vault_id: &str, email: &str, role: Role) -> Result<PublicKeyResponse> {
    let vault = session
        .vault(vault_id)
        .ok_or_else(|| twosecret_core::Error::not_found(format!("vault {vault_id}")))?;
    if !vault.role.can_manage() {
        return Err(twosecret_core::Error::PermissionDenied("you cannot share this vault".into()).into());
    }
    if vault.sync_state != SyncState::Synced {
        sync(session).await?;
    }
    let client = client_for(session)?;
    let user = client.lookup_user(email).await?;
    if user.account_id == session.account().id {
        return Err(twosecret_core::Error::invalid("you already have access to this vault").into());
    }
    let pk = twosecret_core::crypto::PublicKey::from_b64(&user.public_key)?;
    let wrapped = session.wrap_vault_key_for(vault_id, &pk)?;
    client
        .add_member(
            vault_id,
            &AddMemberRequest {
                account_id: user.account_id.clone(),
                role,
                wrapped_key: wrapped,
            },
        )
        .await?;
    sync(session).await?;
    Ok(user)
}

pub async fn vault_members(session: &Session, vault_id: &str) -> Result<Vec<MemberDto>> {
    client_for(session)?.members(vault_id).await
}

pub async fn set_member_role(session: &mut Session, vault_id: &str, account_id: &str, role: Role) -> Result<()> {
    client_for(session)?
        .update_member(vault_id, account_id, &UpdateMemberRequest { role })
        .await?;
    sync(session).await.map(|_| ())
}

pub async fn remove_member(session: &mut Session, vault_id: &str, account_id: &str) -> Result<()> {
    client_for(session)?.remove_member(vault_id, account_id).await?;
    sync(session).await.map(|_| ())
}

/// Change the master password locally and – for server accounts – on the
/// server. Other devices are signed out by the server.
pub async fn change_password(session: &mut Session, current: &str, new: &str, secret_key: &SecretKey) -> Result<()> {
    let change = session.prepare_password_change(current, new, secret_key)?;
    if session.server().is_some() {
        let client = client_for(session)?;
        client
            .change_password(&ChangePasswordRequest {
                current_auth_key: b64(change.current_auth_key.as_bytes()),
                new_auth_key: b64(change.new_auth_key.as_bytes()),
                salt: change.salt.clone(),
                kdf: change.kdf.clone(),
                keyset: change.keyset.clone(),
            })
            .await?;
    }
    session.commit_password_change(&change);
    Ok(())
}

/// Sign this device out of the server (the local data stays).
pub async fn sign_out(session: &mut Session) -> Result<()> {
    if let Ok(client) = client_for(session) {
        let _ = client.logout().await;
    }
    session.clear_server_token();
    Ok(())
}

/// Permanently delete the account and all owned vaults from the server.
/// The local copy is turned into a local-only account.
pub async fn delete_server_account(session: &mut Session, password: &str, secret_key: &SecretKey) -> Result<()> {
    let keys = session.verify_password(password, secret_key)?;
    client_for(session)?
        .delete_account(&b64(keys.auth_key.as_bytes()))
        .await?;
    session.unlink_server();
    Ok(())
}

/// Check all passwords against Have I Been Pwned using k-anonymity: only the
/// first five hex characters of each SHA-1 hash are sent. Returns breach
/// counts by item id.
pub async fn breach_check(session: &Session) -> Result<HashMap<String, u64>> {
    let mut by_prefix: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for (_, item) in session.all_items() {
        if item.is_trashed() {
            continue;
        }
        if let Some(pw) = item.password() {
            let (prefix, suffix) = watchtower::hibp_hash(pw);
            by_prefix.entry(prefix).or_default().push((item.id.clone(), suffix));
        }
    }
    let http = reqwest::Client::new();
    let mut out = HashMap::new();
    for (prefix, entries) in by_prefix {
        let body = http
            .get(watchtower::hibp_url(&prefix))
            .header("Add-Padding", "true")
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        for (id, suffix) in entries {
            let count = watchtower::hibp_range_count(&body, &suffix);
            if count > 0 {
                out.insert(id, count);
            }
        }
    }
    Ok(out)
}
