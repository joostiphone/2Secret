//! iOS and macOS: keeps the AutoFill extension's cache
//! (`twosecret_core::autofill`) up to date while the vault is unlocked and
//! Face ID / Touch ID unlock is on. The extension (`ios/AutoFill`,
//! `macos/AutoFill`) fills passwords, passkeys and verification codes in
//! Safari and other apps.
//!
//! The sealed cache goes into the app group container, its key into the
//! keychain (shared with the extension through the access group), readable
//! only after Face ID or Touch ID with the current enrolment, on this device.

use std::path::PathBuf;

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::AnyThread;
use objc2_authentication_services::{
    ASCredentialIdentity, ASCredentialIdentityStore, ASCredentialServiceIdentifier, ASCredentialServiceIdentifierType,
    ASOneTimeCodeCredentialIdentity, ASPasskeyCredentialIdentity, ASPasswordCredentialIdentity,
};
use objc2_foundation::{NSArray, NSData, NSFileManager, NSOperatingSystemVersion, NSProcessInfo, NSString};
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::passwords::{
    delete_generic_password_options, set_generic_password_options, AccessControlOptions, PasswordOptions,
};
use twosecret_core::autofill::AutofillCache;

const SERVICE: &str = "2Secret AutoFill";
const ACCOUNT: &str = "cache-key";
const FILE: &str = "autofill.cache";
/// The app's theme (`system`, `light`, `dark`) for the extension's panel,
/// which it reads before the vault is unlocked; no secret.
const THEME_FILE: &str = "autofill.theme";

/// The app group (also the keychain access group) shared with the extension.
/// ios/project.yml declares it for both.
#[cfg(target_os = "ios")]
fn group() -> Option<String> {
    Some("group.io.github.joostiphone.twosecret".into())
}

/// The app group shared with the extension: "<Team ID>.io.github.joostiphone
/// .twosecret", which scripts/macos-sign.sh writes into Info.plist when it
/// adds the extension. `None` without one (builds without a Developer ID,
/// `dx serve`) and before macOS 14, which the extension needs.
#[cfg(target_os = "macos")]
fn group() -> Option<String> {
    use objc2_foundation::NSBundle;
    if !system_at_least(14) {
        return None;
    }
    let value = NSBundle::mainBundle().objectForInfoDictionaryKey(&NSString::from_str("TwoSecretAppGroup"))?;
    let group = value.downcast::<NSString>().ok()?.to_string();
    (!group.is_empty()).then_some(group)
}

fn system_at_least(major: isize) -> bool {
    let version = NSOperatingSystemVersion { majorVersion: major, minorVersion: 0, patchVersion: 0 };
    NSProcessInfo::processInfo().isOperatingSystemAtLeastVersion(version)
}

/// Whether AutoFill can fill verification codes: iOS 18 and macOS 15 added
/// them, older systems do not know their credential identity.
fn one_time_codes() -> bool {
    system_at_least(if cfg!(target_os = "ios") { 18 } else { 15 })
}

/// Whether this build has the AutoFill extension.
pub fn available() -> bool {
    group().is_some()
}

fn container(group: &str) -> Option<PathBuf> {
    let url = NSFileManager::defaultManager()
        .containerURLForSecurityApplicationGroupIdentifier(&NSString::from_str(group))?;
    Some(PathBuf::from(url.path()?.to_string()))
}

fn key_options(group: &str) -> PasswordOptions {
    let mut options = PasswordOptions::new_generic_password(SERVICE, ACCOUNT);
    options.set_access_group(group);
    // Access groups and Touch ID protection need the data protection
    // keychain, which macOS only uses when asked (iOS has no other).
    #[cfg(target_os = "macos")]
    options.use_protected_keychain();
    options
}

/// Write a new cache. Fails quietly in builds without the app group (e.g.
/// `dx serve`).
pub fn write(cache: &AutofillCache) {
    let Some(group) = group() else { return };
    match try_write(&group, cache) {
        Ok(()) => publish_identities(cache),
        Err(e) => eprintln!("2Secret: AutoFill is not available: {e}"),
    }
}

/// Tell the extension which theme the app uses (`system`, `light`, `dark`),
/// so its panel matches.
pub fn write_theme(theme: &str) {
    let Some(dir) = group().and_then(|g| container(&g)) else { return };
    let path = dir.join(THEME_FILE);
    if std::fs::read_to_string(&path).ok().as_deref() != Some(theme) {
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(&path, theme);
    }
}

/// Tell the system which websites and accounts 2Secret can fill, for the
/// suggestions above the keyboard or in the password menu and the passkey
/// sheet. Only websites, user names and passkey ids; never passwords, keys
/// or one-time password secrets.
fn publish_identities(cache: &AutofillCache) {
    let s = |text: &str| NSString::from_str(text);
    let service = |domain: &str| unsafe {
        ASCredentialServiceIdentifier::initWithIdentifier_type(
            ASCredentialServiceIdentifier::alloc(),
            &s(domain),
            ASCredentialServiceIdentifierType::Domain,
        )
    };
    let codes = one_time_codes();
    let mut entries: Vec<Retained<ProtocolObject<dyn ASCredentialIdentity>>> = Vec::new();
    for login in &cache.logins {
        if !login.password.is_empty() {
            for domain in &login.domains {
                let identity = unsafe {
                    ASPasswordCredentialIdentity::initWithServiceIdentifier_user_recordIdentifier(
                        ASPasswordCredentialIdentity::alloc(),
                        &service(domain),
                        &s(&login.username),
                        Some(&s(&login.id)),
                    )
                };
                entries.push(ProtocolObject::from_retained(identity));
            }
        }
        if codes && login.totp.is_some() {
            let label = if login.username.is_empty() { &login.title } else { &login.username };
            for domain in &login.domains {
                let identity = unsafe {
                    ASOneTimeCodeCredentialIdentity::initWithServiceIdentifier_label_recordIdentifier(
                        ASOneTimeCodeCredentialIdentity::alloc(),
                        &service(domain),
                        &s(label),
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

fn try_write(group: &str, cache: &AutofillCache) -> Result<(), String> {
    let dir = container(group).ok_or("no app group container")?;
    // macOS gives the folder's path before anything created it.
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let (sealed, key) = cache.seal().map_err(|e| e.to_string())?;
    let tmp = dir.join(format!("{FILE}.tmp"));
    std::fs::write(&tmp, &sealed).map_err(|e| e.to_string())?;

    let _ = delete_generic_password_options(key_options(group));
    let mut options = key_options(group);
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
    let Some(group) = group() else { return };
    unsafe { ASCredentialIdentityStore::sharedStore().removeAllCredentialIdentitiesWithCompletion(None) };
    let _ = delete_generic_password_options(key_options(&group));
    if let Some(dir) = container(&group) {
        let _ = std::fs::remove_file(dir.join(FILE));
        let _ = std::fs::remove_file(dir.join(THEME_FILE));
    }
}
