//! High level account and sync operations shared by the CLI and all apps.

use std::collections::HashMap;

use twosecret_core::api::*;
use twosecret_core::crypto::{derive_keys, AccountPublicKeys, DerivedKeys, KdfParams, SecretKey};
use twosecret_core::profile::{AccountRecord, Role, ServerLink, SyncState};
use twosecret_core::session::{PasswordChange, Session};
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
    connect_with_keys(session, server_url, &keys, invite_code, device_name).await
}

/// Like [`connect`], with keys derived beforehand (e.g. on a worker thread).
pub async fn connect_with_keys(
    session: &mut Session,
    server_url: &str,
    keys: &DerivedKeys,
    invite_code: Option<&str>,
    device_name: &str,
) -> Result<SyncReport> {
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
    let pre = prelogin(server_url, email).await?;
    let salt = unb64(&pre.salt)?;
    let keys = derive_keys(password, secret_key, email, &salt, &pre.kdf)?;
    signin_with_keys(server_url, email, &keys, device_name).await
}

/// First step of signing in: fetch the account's salt and KDF parameters.
pub async fn prelogin(server_url: &str, email: &str) -> Result<PreloginResponse> {
    let pre = Client::new(server_url).prelogin(email).await?;
    pre.kdf.validate()?;
    unb64(&pre.salt)?;
    Ok(pre)
}

/// Second step of signing in, with keys derived from the prelogin answer.
pub async fn signin_with_keys(server_url: &str, email: &str, keys: &DerivedKeys, device_name: &str) -> Result<Session> {
    let url = normalize_server_url(server_url);
    let client = Client::new(&url);
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
        avatar: info.avatar,
        avatar_dirty: false,
        avatar_checked_at: twosecret_core::util::now(),
    };
    let mut session = Session::from_server_account(
        account,
        keys,
        ServerLink { url: url.clone(), token: None, last_sync_at: None, pq_key_published: false },
    )?;
    session.set_server(&url, &resp.token);
    sync(&mut session).await?;
    Ok(session)
}

/// Obtain a fresh token for a linked session (after it expired or was
/// revoked) using the master password.
pub async fn reauthenticate(
    session: &mut Session,
    password: &str,
    secret_key: &SecretKey,
    device_name: &str,
) -> Result<()> {
    let keys = session.verify_password(password, secret_key)?;
    reauthenticate_with_keys(session, &keys, device_name).await
}

pub async fn reauthenticate_with_keys(session: &mut Session, keys: &DerivedKeys, device_name: &str) -> Result<()> {
    let link = session.server().ok_or(Error::NotLinked)?.clone();
    let client = Client::new(&link.url);
    let resp = client
        .login(&LoginRequest {
            email: session.account().email.clone(),
            auth_key: b64(keys.auth_key.as_bytes()),
            device_name: Some(device_name.to_string()),
        })
        .await?;
    if resp.account.keyset != session.account().keyset {
        return Err(Error::Protocol(
            "the master password was changed on another device; remove this account from the device and sign in again"
                .into(),
        ));
    }
    session.set_server(&link.url, &resp.token);
    Ok(())
}

/// Unlock a linked account with the help of the server. Needed after the
/// master password was changed on another device: the local profile still
/// holds the keyset encrypted with the old password. The server's keyset is
/// adopted only if it decrypts with the new password *and* contains the same
/// account key.
pub async fn unlock_online(
    profile: twosecret_core::Profile,
    password: &str,
    secret_key: &SecretKey,
    device_name: &str,
) -> Result<Session> {
    let link = profile.server.clone().ok_or(Error::NotLinked)?;
    let pre = prelogin(&link.url, &profile.account.email).await?;
    let salt = unb64(&pre.salt)?;
    let keys = derive_keys(password, secret_key, &profile.account.email, &salt, &pre.kdf)?;
    unlock_online_with_keys(profile, &keys, device_name).await
}

/// Second half of [`unlock_online`], with keys derived from the server's
/// current salt and KDF parameters.
pub async fn unlock_online_with_keys(
    mut profile: twosecret_core::Profile,
    keys: &DerivedKeys,
    device_name: &str,
) -> Result<Session> {
    let link = profile.server.clone().ok_or(Error::NotLinked)?;
    let resp = Client::new(&link.url)
        .login(&LoginRequest {
            email: profile.account.email.clone(),
            auth_key: b64(keys.auth_key.as_bytes()),
            device_name: Some(device_name.to_string()),
        })
        .await?;
    let info = resp.account;
    if info.account_id != profile.account.id {
        return Err(Error::Protocol("the server returned a different account".into()));
    }
    let new_keyset = twosecret_core::crypto::Keyset::decrypt(&info.keyset, &keys.master_key)?;
    // If we can still open the old keyset, make sure it is the same account key.
    if let Ok(session) = Session::open(profile.clone(), keys) {
        if session.account_key() != &new_keyset.account_key {
            return Err(Error::Protocol("the account key on the server does not match this device".into()));
        }
    }
    profile.account.salt = info.salt;
    profile.account.kdf = info.kdf;
    profile.account.keyset = info.keyset;
    profile.account.name = info.name;
    let mut session = Session::open(profile, keys)?;
    session.set_server(&link.url, &resp.token);
    Ok(session)
}

/// Access to a session that may live elsewhere (e.g. inside a UI signal).
///
/// [`sync_with`] only borrows the session for short, synchronous steps and
/// never across network calls, so apps stay responsive (and editable) while
/// syncing.
pub trait SessionAccess {
    /// Run `f` on the session. Fails when the session is gone (locked).
    fn with_session<R>(&mut self, f: impl FnOnce(&mut Session) -> R) -> Result<R>;
}

impl SessionAccess for &mut Session {
    fn with_session<R>(&mut self, f: impl FnOnce(&mut Session) -> R) -> Result<R> {
        Ok(f(self))
    }
}

/// Synchronise all vaults with the server.
pub async fn sync(session: &mut Session) -> Result<SyncReport> {
    let mut access = session;
    sync_with(&mut access).await
}

/// Synchronise using short-lived borrows of the session (see [`SessionAccess`]).
pub async fn sync_with<A: SessionAccess>(access: &mut A) -> Result<SyncReport> {
    let client = access.with_session(|s| client_for(s))??;

    let creates = access.with_session(|s| s.vaults_pending(SyncState::PendingCreate))?;
    for v in creates {
        client
            .create_vault(&CreateVaultRequest {
                id: v.id.clone(),
                meta: v.meta.clone(),
                wrapped_key: v.wrapped_key.clone(),
            })
            .await?;
        access.with_session(|s| s.mark_vault_synced(&v.id))?;
    }
    let updates = access.with_session(|s| s.vaults_pending(SyncState::PendingUpdate))?;
    for v in updates {
        if v.role.can_manage() {
            let req = UpdateVaultRequest { meta: v.meta.clone(), key_rev: Some(v.key_rev) };
            match client.update_vault(&v.id, &req).await {
                Ok(()) => {}
                Err(e) if e.is_not_found() || e.status() == Some(403) => {}
                // The vault key was replaced: the sync below re-encrypts the
                // name with the new key, and the next sync sends it.
                Err(e) if e.status() == Some(409) => continue,
                Err(e) => return Err(e),
            }
        }
        // Only mark synced if the metadata was not changed again meanwhile.
        access.with_session(|s| {
            if s.profile().vault(&v.id).is_some_and(|cur| cur.meta == v.meta) {
                s.mark_vault_synced(&v.id);
            }
        })?;
    }
    let deletes = access.with_session(|s| s.vaults_pending(SyncState::PendingDelete))?;
    for v in deletes {
        match client.delete_vault(&v.id).await {
            Ok(()) => {}
            Err(e) if e.is_not_found() => {}
            Err(e) => return Err(e),
        }
        access.with_session(|s| s.forget_vault(&v.id))?;
    }

    let mut total = SyncReport::default();
    for _ in 0..5 {
        let req = access.with_session(|s| s.sync_request())?;
        let resp = client.sync(&req).await?;
        let (report, dirty) = access.with_session(|s| -> Result<(SyncReport, bool)> {
            let report = s.apply_sync_response_for(Some(&req), resp)?;
            let dirty = s
                .profile()
                .items
                .iter()
                .any(|i| i.dirty && s.profile().vault(&i.vault_id).is_some_and(|v| v.role.can_write()));
            Ok((report, dirty))
        })??;
        total.merge(&report);
        // Changes over the server's storage limit stay waiting; another
        // round now would not help.
        if !report.needs_another_round && (!dirty || report.over_quota > 0) && report.vaults_added == 0 {
            break;
        }
    }
    total.needs_another_round = false;
    post_quantum_upkeep(&client, access).await?;
    total.avatar_changed = avatar_upkeep(&client, access).await?;
    Ok(total)
}

/// Send a profile photo changed here, or (at most hourly) take one changed on
/// another device. Servers from before 1.5 answer 404 or 405: the photo then
/// stays on this device.
async fn avatar_upkeep<A: SessionAccess>(client: &Client, access: &mut A) -> Result<bool> {
    let unsupported = |e: &Error| e.is_not_found() || e.status() == Some(405);
    if let Some(avatar) = access.with_session(|s| s.avatar_to_upload())? {
        match client.set_avatar(&SetAvatarRequest { avatar: avatar.clone() }).await {
            Ok(()) => access.with_session(|s| s.mark_avatar_uploaded(&avatar))?,
            Err(e) if unsupported(&e) => {}
            Err(e) => return Err(e),
        }
        return Ok(false);
    }
    if !access.with_session(|s| s.avatar_check_due())? {
        return Ok(false);
    }
    let account = client.account().await?;
    access.with_session(|s| s.apply_server_avatar(account.avatar))
}

/// Publish our ML-KEM key, and store vault keys that others shared with us
/// wrapped with our own account key, so the server keeps nothing a future
/// quantum computer could open. Servers from before this feature answer 404
/// or 405; that is not an error.
async fn post_quantum_upkeep<A: SessionAccess>(client: &Client, access: &mut A) -> Result<()> {
    let unsupported = |e: &Error| e.is_not_found() || e.status() == Some(405);
    if let Some(pq_public_key) = access.with_session(|s| s.pq_key_to_publish())? {
        match client.set_pq_key(&SetPqKeyRequest { pq_public_key }).await {
            Ok(()) => access.with_session(|s| s.mark_pq_key_published())?,
            Err(e) if unsupported(&e) => {}
            Err(e) => return Err(e),
        }
    }
    for rewrap in access.with_session(|s| s.vault_keys_to_rewrap())? {
        let req = SetVaultKeyRequest { wrapped_key: rewrap.wrapped_key.clone(), key_rev: Some(rewrap.key_rev) };
        match client.set_vault_key(&rewrap.vault_id, &req).await {
            Ok(()) => access.with_session(|s| s.set_vault_wrapped_key(&rewrap.vault_id, rewrap.wrapped_key))?,
            // Unsupported, or the key was replaced meanwhile (next sync).
            Err(e) if unsupported(&e) || e.status() == Some(409) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Share a vault with another account on the same server.
pub async fn share_vault(session: &mut Session, vault_id: &str, email: &str, role: Role) -> Result<PublicKeyResponse> {
    let vault = session.vault(vault_id).ok_or_else(|| twosecret_core::Error::not_found(format!("vault {vault_id}")))?;
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
    let keys = AccountPublicKeys::from_b64(&user.public_key, user.pq_public_key.as_deref())?;
    let wrapped = session.wrap_vault_key_for(vault_id, &keys)?;
    let key_rev = session.profile().vault(vault_id).map(|v| v.key_rev);
    client
        .add_member(
            vault_id,
            &AddMemberRequest { account_id: user.account_id.clone(), role, wrapped_key: wrapped, key_rev },
        )
        .await?;
    sync(session).await?;
    Ok(user)
}

pub async fn vault_members(session: &Session, vault_id: &str) -> Result<Vec<MemberDto>> {
    client_for(session)?.members(vault_id).await
}

pub async fn set_member_role(session: &mut Session, vault_id: &str, account_id: &str, role: Role) -> Result<()> {
    client_for(session)?.update_member(vault_id, account_id, &UpdateMemberRequest { role }).await?;
    sync(session).await.map(|_| ())
}

/// Remove someone from a vault, then replace the vault key so that whatever
/// is added or changed from now on is unreadable with the key they had.
pub async fn remove_member(session: &mut Session, vault_id: &str, account_id: &str) -> Result<()> {
    client_for(session)?.remove_member(vault_id, account_id).await?;
    if account_id == session.account().id {
        // We left the vault ourselves.
        return sync(session).await.map(|_| ());
    }
    rotate_vault_key(session, vault_id).await
}

/// Replace a vault's key: a new random key, the vault re-encrypted with it,
/// and the key wrapped for every current member. Retried when another device
/// changed the vault at the same moment.
pub async fn rotate_vault_key(session: &mut Session, vault_id: &str) -> Result<()> {
    let client = client_for(session)?;
    let mut attempts = 0;
    loop {
        sync(session).await?;
        let members = client.members(vault_id).await?;
        let req = session.rotate_vault_key_request(vault_id, &members)?;
        match client.rotate_vault_key(vault_id, &req).await {
            Ok(()) => break,
            Err(e) if e.status() == Some(409) && attempts < 3 => attempts += 1,
            Err(e) => return Err(e),
        }
    }
    sync(session).await.map(|_| ())
}

/// Change the master password locally and – for server accounts – on the
/// server. Other devices are signed out by the server.
pub async fn change_password(session: &mut Session, current: &str, new: &str, secret_key: &SecretKey) -> Result<()> {
    let change = session.prepare_password_change(current, new, secret_key)?;
    submit_password_change(session, &change).await
}

/// Send a prepared password change to the server (if any) and apply it.
pub async fn submit_password_change(session: &mut Session, change: &PasswordChange) -> Result<()> {
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
    session.commit_password_change(change);
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
    delete_server_account_with_keys(session, &keys).await
}

pub async fn delete_server_account_with_keys(session: &mut Session, keys: &DerivedKeys) -> Result<()> {
    client_for(session)?.delete_account(&b64(keys.auth_key.as_bytes())).await?;
    session.unlink_server();
    Ok(())
}

/// Check all passwords against Have I Been Pwned using k-anonymity: only the
/// first five hex characters of each SHA-1 hash are sent. Returns breach
/// counts by item id.
pub async fn breach_check(session: &Session) -> Result<HashMap<String, u64>> {
    breach_check_hashes(breach_check_prepare(session)).await
}

/// Hash all passwords (item id, SHA-1 prefix, SHA-1 suffix) so the network
/// part can run without access to the session.
pub fn breach_check_prepare(session: &Session) -> Vec<(String, String, String)> {
    session
        .all_items()
        .filter(|(_, item)| !item.is_trashed())
        .filter_map(|(_, item)| {
            item.password().map(|pw| {
                let (prefix, suffix) = watchtower::hibp_hash(pw);
                (item.id.clone(), prefix, suffix)
            })
        })
        .collect()
}

/// Query the Have I Been Pwned range API for prepared hashes.
pub async fn breach_check_hashes(entries: Vec<(String, String, String)>) -> Result<HashMap<String, u64>> {
    let mut by_prefix: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for (id, prefix, suffix) in entries {
        by_prefix.entry(prefix).or_default().push((id, suffix));
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
