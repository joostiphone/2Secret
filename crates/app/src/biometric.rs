//! Touch ID, Face ID and Windows Hello: the platform side of
//! [`twosecret_core::biometric`].
//!
//! The operating system keeps a random 256-bit *device key* and releases it
//! only after a biometric check:
//!
//! - **iOS**: a keychain item that the Secure Enclave only opens after Face ID
//!   or Touch ID with the currently enrolled fingers or face, and only while
//!   the device has a passcode (`ThisDeviceOnly`, never in backups or iCloud).
//! - **macOS**: Touch ID through LocalAuthentication, the key in the login
//!   keychain, readable only by this app.
//! - **Windows**: the device key is derived from a Windows Hello signature
//!   over a fixed challenge. The private key never leaves the TPM and the
//!   device key is never stored.
//!
//! All functions block (they may show a system prompt): call them through
//! `platform::run_heavy`.

use twosecret_core::crypto::SymmetricKey;

// Each platform offers only its own kinds; Linux, the BSDs and the web none.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    TouchId,
    FaceId,
    OpticId,
    WindowsHello,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::TouchId => "Touch ID",
            Kind::FaceId => "Face ID",
            Kind::OpticId => "Optic ID",
            Kind::WindowsHello => "Windows Hello",
        }
    }
}

#[cfg_attr(not(any(target_os = "macos", target_os = "ios", windows)), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The person cancelled the prompt or chose to type their password.
    Cancelled,
    /// Not available on this device (any more), e.g. no fingers enrolled.
    Unavailable,
    Failed(String),
}

/// The biometric method this device offers, if any. Shows no prompt.
pub fn available() -> Option<Kind> {
    imp::available()
}

/// Create a new device key for the account and hand it to the operating
/// system. May show a prompt.
pub fn create_device_key(account_id: &str, reason: &str) -> Result<SymmetricKey, Error> {
    imp::create_device_key(account_id, reason)
}

/// The account's device key, after a successful biometric check.
pub fn device_key(account_id: &str, reason: &str) -> Result<SymmetricKey, Error> {
    imp::device_key(account_id, reason)
}

/// Forget the account's device key.
pub fn delete_device_key(account_id: &str) {
    imp::delete_device_key(account_id)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod imp {
    use super::{Error, Kind};
    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LABiometryType, LAContext, LAError, LAPolicy};
    use security_framework::passwords::{
        delete_generic_password_options, generic_password, set_generic_password_options, PasswordOptions,
    };
    use twosecret_core::crypto::SymmetricKey;

    const SERVICE: &str = "2Secret biometric unlock";
    const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;

    fn kind_of(context: &LAContext) -> Option<Kind> {
        unsafe { context.canEvaluatePolicy_error(POLICY) }.ok()?;
        match unsafe { context.biometryType() } {
            LABiometryType::TouchID => Some(Kind::TouchId),
            LABiometryType::FaceID => Some(Kind::FaceId),
            LABiometryType::OpticID => Some(Kind::OpticId),
            _ => None,
        }
    }

    pub fn available() -> Option<Kind> {
        let context = unsafe { LAContext::new() };
        kind_of(&context)
    }

    /// Show the biometric prompt; on success the returned context counts as
    /// authenticated for the keychain read that follows.
    fn authenticate(reason: &str) -> Result<Retained<LAContext>, Error> {
        let context = unsafe { LAContext::new() };
        if kind_of(&context).is_none() {
            return Err(Error::Unavailable);
        }
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), Error>>();
        let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
            let result = if success.as_bool() {
                Ok(())
            } else {
                let code = unsafe { error.as_ref() }.map(|e| e.code()).unwrap_or(0);
                match LAError(code) {
                    LAError::UserCancel | LAError::AppCancel | LAError::SystemCancel | LAError::UserFallback => {
                        Err(Error::Cancelled)
                    }
                    LAError::BiometryNotAvailable | LAError::BiometryNotEnrolled | LAError::BiometryLockout => {
                        Err(Error::Unavailable)
                    }
                    _ => Err(Error::Failed(format!("authentication failed ({code})"))),
                }
            };
            let _ = tx.send(result);
        });
        unsafe { context.evaluatePolicy_localizedReason_reply(POLICY, &NSString::from_str(reason), &reply) };
        rx.recv().map_err(|_| Error::Failed("no answer from LocalAuthentication".into()))??;
        Ok(context)
    }

    fn options(account_id: &str) -> PasswordOptions {
        #[allow(unused_mut)]
        let mut options = PasswordOptions::new_generic_password(SERVICE, account_id);
        // iOS: the Secure Enclave releases the key only after Face ID / Touch
        // ID with the current enrolment, on this device, with a passcode set.
        #[cfg(target_os = "ios")]
        {
            use security_framework::access_control::{ProtectionMode, SecAccessControl};
            use security_framework::passwords::AccessControlOptions;
            if let Ok(acl) = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
                AccessControlOptions::BIOMETRY_CURRENT_SET.bits(),
            ) {
                options.set_access_control(acl);
            }
        }
        options
    }

    pub fn create_device_key(account_id: &str, reason: &str) -> Result<SymmetricKey, Error> {
        authenticate(reason)?;
        delete_device_key(account_id);
        let key = SymmetricKey::generate();
        set_generic_password_options(key.as_bytes(), options(account_id))
            .map_err(|e| Error::Failed(format!("keychain: {e}")))?;
        Ok(key)
    }

    pub fn device_key(account_id: &str, reason: &str) -> Result<SymmetricKey, Error> {
        #[allow(unused_variables)]
        let context = authenticate(reason)?;
        #[allow(unused_mut)]
        let mut options = options(account_id);
        // Reuse the authenticated context, so iOS does not prompt twice.
        #[cfg(target_os = "ios")]
        {
            use core_foundation::base::{CFType, TCFType};
            use core_foundation::string::CFString;
            use security_framework_sys::item::kSecUseAuthenticationContext;
            let raw = Retained::as_ptr(&context) as core_foundation::base::CFTypeRef;
            #[allow(deprecated)]
            options.query.push((unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationContext) }, unsafe {
                CFType::wrap_under_get_rule(raw)
            }));
        }
        let bytes = generic_password(options).map_err(|e| match e.code() {
            -25300 => Error::Unavailable, // errSecItemNotFound
            -128 => Error::Cancelled,     // errSecUserCanceled
            _ => Error::Failed(format!("keychain: {e}")),
        })?;
        let key = SymmetricKey::from_slice(&bytes).map_err(|_| Error::Unavailable);
        drop(context);
        key
    }

    pub fn delete_device_key(account_id: &str) {
        let _ = delete_generic_password_options(PasswordOptions::new_generic_password(SERVICE, account_id));
    }
}

#[cfg(windows)]
mod imp {
    use super::{Error, Kind};
    use twosecret_core::crypto::{hkdf32, SymmetricKey};
    use windows::core::{Array, HSTRING};
    use windows::Security::Credentials::{
        KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };
    use windows::Security::Cryptography::CryptographicBuffer;
    use windows::Win32::System::WinRT::{RoInitialize, RO_INIT_MULTITHREADED};

    /// Signed with the Windows Hello key; the signature (RSA PKCS #1 v1.5,
    /// deterministic) is the input for the device key.
    const CHALLENGE: &[u8] = b"2secret/v1/windows-hello/device-key";

    fn init() {
        // Fails harmlessly when the thread already joined an apartment.
        let _ = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
    }

    fn failed(e: windows::core::Error) -> Error {
        Error::Failed(format!("Windows Hello: {e}"))
    }

    fn check(status: KeyCredentialStatus) -> Result<(), Error> {
        match status {
            KeyCredentialStatus::Success => Ok(()),
            KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => Err(Error::Cancelled),
            KeyCredentialStatus::NotFound => Err(Error::Unavailable),
            other => Err(Error::Failed(format!("Windows Hello: status {}", other.0))),
        }
    }

    fn name(account_id: &str) -> HSTRING {
        HSTRING::from(format!("2Secret {account_id}"))
    }

    pub fn available() -> Option<Kind> {
        init();
        let supported = KeyCredentialManager::IsSupportedAsync().ok()?.get().ok()?;
        supported.then_some(Kind::WindowsHello)
    }

    fn sign(credential: &KeyCredential) -> Result<SymmetricKey, Error> {
        let data = CryptographicBuffer::CreateFromByteArray(CHALLENGE).map_err(failed)?;
        let result = credential.RequestSignAsync(&data).map_err(failed)?.get().map_err(failed)?;
        check(result.Status().map_err(failed)?)?;
        let mut signature = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&result.Result().map_err(failed)?, &mut signature).map_err(failed)?;
        Ok(hkdf32(&signature, Some(CHALLENGE), b"2secret/v1/windows-hello/key"))
    }

    pub fn create_device_key(account_id: &str, _reason: &str) -> Result<SymmetricKey, Error> {
        init();
        let result =
            KeyCredentialManager::RequestCreateAsync(&name(account_id), KeyCredentialCreationOption::ReplaceExisting)
                .map_err(failed)?
                .get()
                .map_err(failed)?;
        check(result.Status().map_err(failed)?)?;
        sign(&result.Credential().map_err(failed)?)
    }

    pub fn device_key(account_id: &str, _reason: &str) -> Result<SymmetricKey, Error> {
        init();
        let result = KeyCredentialManager::OpenAsync(&name(account_id)).map_err(failed)?.get().map_err(failed)?;
        check(result.Status().map_err(failed)?)?;
        sign(&result.Credential().map_err(failed)?)
    }

    pub fn delete_device_key(account_id: &str) {
        init();
        if let Ok(op) = KeyCredentialManager::DeleteAsync(&name(account_id)) {
            let _ = op.get();
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios", windows)))]
mod imp {
    use super::{Error, Kind};
    use twosecret_core::crypto::SymmetricKey;

    pub fn available() -> Option<Kind> {
        None
    }

    pub fn create_device_key(_account_id: &str, _reason: &str) -> Result<SymmetricKey, Error> {
        Err(Error::Unavailable)
    }

    pub fn device_key(_account_id: &str, _reason: &str) -> Result<SymmetricKey, Error> {
        Err(Error::Unavailable)
    }

    pub fn delete_device_key(_account_id: &str) {}
}
