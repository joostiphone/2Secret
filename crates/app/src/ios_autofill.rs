//! iOS: keeps the AutoFill extension's cache (`twosecret_core::autofill`) up
//! to date while the vault is unlocked and Face ID / Touch ID unlock is on.
//!
//! The sealed cache goes into the app group container, its key into the
//! keychain (shared with the extension through the app group), readable only
//! after Face ID or Touch ID with the current enrolment, on this device.

use std::path::PathBuf;

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::AnyThread;
use objc2_authentication_services::{
    ASCredentialIdentity, ASCredentialIdentityStore, ASCredentialServiceIdentifier, ASCredentialServiceIdentifierType,
    ASPasskeyCredentialIdentity, ASPasswordCredentialIdentity,
};
use objc2_foundation::{NSArray, NSData, NSFileManager, NSString};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::passwords::{
    delete_generic_password_options, set_generic_password_options, AccessControlOptions, PasswordOptions,
};
use twosecret_core::autofill::AutofillCache;

/// Shared with the extension (ios/project.yml declares it for both).
const GROUP: &str = "group.io.github.joostiphone.twosecret";
const SERVICE: &str = "2Secret AutoFill";
const ACCOUNT: &str = "cache-key";
const FILE: &str = "autofill.cache";

fn container() -> Option<PathBuf> {
    let url = NSFileManager::defaultManager()
        .containerURLForSecurityApplicationGroupIdentifier(&NSString::from_str(GROUP))?;
    Some(PathBuf::from(url.path()?.to_string()))
}

fn key_options() -> PasswordOptions {
    let mut options = PasswordOptions::new_generic_password(SERVICE, ACCOUNT);
    options.set_access_group(GROUP);
    options
}

/// Write a new cache. Fails quietly in builds without the app group (e.g.
/// `dx serve`).
pub fn write(cache: &AutofillCache) {
    match try_write(cache) {
        Ok(()) => publish_identities(cache),
        Err(e) => eprintln!("2Secret: AutoFill is not available: {e}"),
    }
}

/// Tell iOS which websites and accounts 2Secret can fill, for the
/// suggestions above the keyboard and the passkey sheet. Only websites, user
/// names and passkey ids; never passwords or keys.
fn publish_identities(cache: &AutofillCache) {
    let s = |text: &str| NSString::from_str(text);
    let mut entries: Vec<Retained<ProtocolObject<dyn ASCredentialIdentity>>> = Vec::new();
    for login in &cache.logins {
        if !login.password.is_empty() {
            for domain in &login.domains {
                let service = unsafe {
                    ASCredentialServiceIdentifier::initWithIdentifier_type(
                        ASCredentialServiceIdentifier::alloc(),
                        &s(domain),
                        ASCredentialServiceIdentifierType::Domain,
                    )
                };
                let identity = unsafe {
                    ASPasswordCredentialIdentity::initWithServiceIdentifier_user_recordIdentifier(
                        ASPasswordCredentialIdentity::alloc(),
                        &service,
                        &s(&login.username),
                        Some(&s(&login.id)),
                    )
                };
                entries.push(ProtocolObject::from_retained(identity));
            }
        }
        for passkey in &login.passkeys {
            let (Ok(id), Ok(handle)) = (
                twosecret_core::util::unb64url(&passkey.credential_id),
                twosecret_core::util::unb64url(&passkey.user_handle),
            ) else {
                continue;
            };
            let identity = unsafe {
                ASPasskeyCredentialIdentity::initWithRelyingPartyIdentifier_userName_credentialID_userHandle_recordIdentifier(
                    ASPasskeyCredentialIdentity::alloc(),
                    &s(&passkey.rp_id),
                    &s(&passkey.user_name),
                    &NSData::with_bytes(&id),
                    &NSData::with_bytes(&handle),
                    Some(&s(&login.id)),
                )
            };
            entries.push(ProtocolObject::from_retained(identity));
        }
    }
    let array = NSArray::from_retained_slice(&entries);
    unsafe { ASCredentialIdentityStore::sharedStore().replaceCredentialIdentityEntries_completion(&array, None) };
}

fn try_write(cache: &AutofillCache) -> Result<(), String> {
    let dir = container().ok_or("no app group container")?;
    let (sealed, key) = cache.seal().map_err(|e| e.to_string())?;
    let tmp = dir.join(format!("{FILE}.tmp"));
    std::fs::write(&tmp, &sealed).map_err(|e| e.to_string())?;

    let _ = delete_generic_password_options(key_options());
    let mut options = key_options();
    let acl = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        AccessControlOptions::BIOMETRY_CURRENT_SET.bits(),
    )
    .map_err(|e| e.to_string())?;
    options.set_access_control(acl);
    set_generic_password_options(key.as_bytes(), options).map_err(|e| format!("keychain: {e}"))?;
    std::fs::rename(&tmp, dir.join(FILE)).map_err(|e| e.to_string())
}

/// Remove the cache and its key (AutoFill stops working).
pub fn clear() {
    unsafe { ASCredentialIdentityStore::sharedStore().removeAllCredentialIdentitiesWithCompletion(None) };
    let _ = delete_generic_password_options(key_options());
    if let Some(dir) = container() {
        let _ = std::fs::remove_file(dir.join(FILE));
    }
}
