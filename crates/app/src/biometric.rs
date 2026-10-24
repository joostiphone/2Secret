//! Touch ID, Face ID and Windows Hello: the platform side of
//! [`twosecret_core::biometric`].
//!
//! The operating system keeps a random 256-bit *device key* and releases it
//! only after a biometric check:
//!
//! - **iOS and macOS**: a keychain item that the Secure Enclave only opens
//!   after Face ID or Touch ID with the currently enrolled fingers or face,
//!   and only while the device has a passcode (`ThisDeviceOnly`, never in
//!   backups or iCloud). On a Mac the item is in the data protection
//!   keychain: the login keychain knows no such protection, and a copy of it
//!   opens with the login password alone.
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
    use core_foundation::base::{CFType, CFTypeRef, TCFType};
    use core_foundation::string::CFString;
    use objc2::rc::Retained;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LABiometryType, LAContext, LAError, LAPolicy};
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::passwords::{
        delete_generic_password_options, generic_password, set_generic_password_options, AccessControlOptions,
        PasswordOptions,
    };
    use security_framework_sys::item::kSecUseAuthenticationContext;
    use twosecret_core::crypto::SymmetricKey;
    use zeroize::Zeroizing;

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

    /// The keychain item with the device key: in the data protection
    /// keychain, the only one iOS has and the only one on a Mac that knows
    /// biometric protection (macOS uses it when asked).
    fn options(account_id: &str) -> PasswordOptions {
        #[allow(unused_mut)]
        let mut options = PasswordOptions::new_generic_password(SERVICE, account_id);
        #[cfg(target_os = "macos")]
        options.use_protected_keychain();
        options
    }

    /// The item as it is created: the Secure Enclave releases it only after
    /// Face ID / Touch ID with the current enrolment, on this device, while a
    /// passcode (on a Mac: a login password) is set. Without that protection
    /// the key is not stored at all.
    fn protected_options(account_id: &str) -> Result<PasswordOptions, Error> {
        let acl = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
            AccessControlOptions::BIOMETRY_CURRENT_SET.bits(),
        )
        .map_err(keychain_error)?;
        let mut options = options(account_id);
        options.set_access_control(acl);
        Ok(options)
    }

    fn keychain_error(e: security_framework::base::Error) -> Error {
        match e.code() {
            -25300 => Error::Unavailable, // errSecItemNotFound
            -128 => Error::Cancelled,     // errSecUserCanceled
            _ => Error::Failed(format!("keychain: {e}")),
        }
    }

    pub fn create_device_key(account_id: &str, reason: &str) -> Result<SymmetricKey, Error> {
        authenticate(reason)?;
        delete_device_key(account_id);
        let key = SymmetricKey::generate();
        set_generic_password_options(key.as_bytes(), protected_options(account_id)?).map_err(keychain_error)?;
        Ok(key)
    }

    pub fn device_key(account_id: &str, reason: &str) -> Result<SymmetricKey, Error> {
        let context = authenticate(reason)?;
        let mut options = options(account_id);
        // Reuse the authenticated context, so the system does not prompt twice.
        let raw = Retained::as_ptr(&context) as CFTypeRef;
        #[allow(deprecated)]
        options.query.push((unsafe { CFString::wrap_under_get_rule(kSecUseAuthenticationContext) }, unsafe {
            CFType::wrap_under_get_rule(raw)
        }));
        let bytes = match generic_password(options) {
            Ok(bytes) => Zeroizing::new(bytes),
            // 2Secret before 1.9.4 kept the key in the Mac's login keychain,
            // which knows no Touch ID protection: move it.
            #[cfg(target_os = "macos")]
            Err(e) if e.code() == -25300 => move_from_login_keychain(account_id)?,
            Err(e) => return Err(keychain_error(e)),
        };
        let key = SymmetricKey::from_slice(&bytes).map_err(|_| Error::Unavailable);
        drop(context);
        key
    }

    #[cfg(target_os = "macos")]
    fn move_from_login_keychain(account_id: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
        let legacy = || PasswordOptions::new_generic_password(SERVICE, account_id);
        let bytes = Zeroizing::new(generic_password(legacy()).map_err(keychain_error)?);
        set_generic_password_options(&bytes, protected_options(account_id)?).map_err(keychain_error)?;
        let _ = delete_generic_password_options(legacy());
        Ok(bytes)
    }

    pub fn delete_device_key(account_id: &str) {
        let _ = delete_generic_password_options(options(account_id));
        // The login keychain item of 2Secret before 1.9.4 on a Mac.
        #[cfg(target_os = "macos")]
        let _ = delete_generic_password_options(PasswordOptions::new_generic_password(SERVICE, account_id));
    }
}

#[cfg(windows)]
mod imp {
    use super::{Error, Kind};
    use twosecret_core::crypto::{hkdf32, SymmetricKey};
    use windows::core::{w, Array, HSTRING, PCWSTR};
    use windows::Security::Credentials::{
        KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };
    use windows::Security::Cryptography::CryptographicBuffer;
    use windows::Win32::System::WinRT::{RoInitialize, RO_INIT_MULTITHREADED};
    use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow};

    /// Signed with the Windows Hello key; the signature (RSA PKCS #1 v1.5,
    /// deterministic) is the input for the device key.
    const CHALLENGE: &[u8] = b"2secret/v1/windows-hello/device-key";

    /// WINBIO_E_INVALID_TICKET: a face or fingerprint confirmed in a prompt
    /// that stayed behind other windows for a few seconds no longer counts.
    const INVALID_TICKET: u32 = 0x8009_8044;

    /// Windows often opens the Windows Hello prompt of a desktop app behind
    /// its window. Bring it to the front once it shows (the app is in front,
    /// as it was just clicked, so Windows lets it hand over the focus).
    fn focus_prompt() {
        std::thread::spawn(|| {
            for _ in 0..20 {
                std::thread::sleep(std::time::Duration::from_millis(150));
                if let Ok(prompt) = unsafe { FindWindowW(w!("Credential Dialog Xaml Host"), PCWSTR::null()) } {
                    let _ = unsafe { SetForegroundWindow(prompt) };
                    return;
                }
            }
        });
    }

    /// Ask Windows Hello with its prompt in front, and once more when the
    /// confirmation came too late.
    fn prompt<T>(request: impl Fn() -> windows::core::Result<T>) -> Result<T, Error> {
        focus_prompt();
        match request() {
            Err(e) if e.code().0 as u32 == INVALID_TICKET => {
                focus_prompt();
                request().map_err(failed)
            }
            result => result.map_err(failed),
        }
    }

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
        let result = prompt(|| credential.RequestSignAsync(&data)?.get())?;
        check(result.Status().map_err(failed)?)?;
        let mut signature = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&result.Result().map_err(failed)?, &mut signature).map_err(failed)?;
        Ok(hkdf32(&signature, Some(CHALLENGE), b"2secret/v1/windows-hello/key"))
    }

    pub fn create_device_key(account_id: &str, _reason: &str) -> Result<SymmetricKey, Error> {
        init();
        let result = prompt(|| {
            KeyCredentialManager::RequestCreateAsync(&name(account_id), KeyCredentialCreationOption::ReplaceExisting)?
                .get()
        })?;
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
