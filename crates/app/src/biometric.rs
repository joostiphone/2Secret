//! Touch ID, Face ID, Windows Hello and Android's fingerprint or face
//! unlock: the platform side of [`twosecret_core::biometric`].
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
//! - **Android** (9 and newer): the device key is stored encrypted
//!   (AES-256-GCM) with an Android Keystore key that only works after a
//!   strong (class 3) fingerprint or face check, for every use, and that
//!   Android deletes for good when a fingerprint or face is added or all are
//!   removed. The prompt is the system's `BiometricPrompt`, bound to that
//!   key's cipher (Biometric in crates/app/android/MainActivity.kt).
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
    /// Android: whatever strong biometric the phone has (mostly a
    /// fingerprint, on some phones the face).
    AndroidBiometric,
}

impl Kind {
    /// The method's name, for "{kind}" in texts (`state::with_kind`). Apple's
    /// and Microsoft's names are the same in every language; Android's is a
    /// plain description, so it is translated.
    pub fn label(self) -> &'static str {
        match self {
            Kind::TouchId => "Touch ID",
            Kind::FaceId => "Face ID",
            Kind::OpticId => "Optic ID",
            Kind::WindowsHello => "Windows Hello",
            Kind::AndroidBiometric => crate::i18n::t("biometric.android"),
        }
    }
}

// Windows Hello knows fewer of these than Apple's systems.
#[cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The person cancelled the prompt or chose to type their password.
    Cancelled,
    /// The system could not ask right now: the app was not in front yet
    /// (just started or coming back), or another prompt was showing. Asking
    /// again a moment later works.
    NotNow,
    /// Not available on this device (any more), and why.
    Unavailable(Why),
    Failed(String),
}

/// Why biometric unlock is not available.
#[cfg_attr(not(any(target_os = "macos", target_os = "ios")), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// No biometry, nothing enrolled, or no device passcode.
    Off,
    /// Locked after too many failed attempts; unlocking the device with its
    /// passcode turns it on again.
    Lockout,
    /// The device key is gone: the enrolled fingers or face changed (the
    /// system then forgets the key), or it was removed. Biometric unlock has
    /// to be turned on again.
    KeyGone,
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
    use super::{Error, Kind, Why};
    use block2::RcBlock;
    use core_foundation::base::{CFType, CFTypeRef, TCFType};
    use core_foundation::string::CFString;
    use objc2::rc::Retained;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LABiometryType, LAContext, LAPolicy};
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

    /// What a LocalAuthentication error code means here.
    fn la_error(code: isize) -> Error {
        match code {
            // UserCancel, UserFallback (the person chose the password)
            -2 | -3 => Error::Cancelled,
            // SystemCancel, AppCancel, InvalidContext, NotInteractive (the
            // app was not in front, or another prompt was showing)
            -4 | -9 | -10 | -1004 => Error::NotNow,
            // PasscodeNotSet, BiometryNotAvailable, BiometryNotEnrolled
            -7..=-5 => Error::Unavailable(Why::Off),
            // BiometryLockout
            -8 => Error::Unavailable(Why::Lockout),
            _ => Error::Failed(format!("authentication failed ({code})")),
        }
    }

    /// The kind of biometry the context can use, or why it cannot.
    fn kind_of(context: &LAContext) -> Result<Kind, Error> {
        unsafe { context.canEvaluatePolicy_error(POLICY) }.map_err(|e| la_error(e.code()))?;
        match unsafe { context.biometryType() } {
            LABiometryType::TouchID => Ok(Kind::TouchId),
            LABiometryType::FaceID => Ok(Kind::FaceId),
            LABiometryType::OpticID => Ok(Kind::OpticId),
            _ => Err(Error::Unavailable(Why::Off)),
        }
    }

    pub fn available() -> Option<Kind> {
        let context = unsafe { LAContext::new() };
        kind_of(&context).ok()
    }

    /// Show the biometric prompt; on success the returned context counts as
    /// authenticated for the keychain read that follows.
    fn authenticate(reason: &str) -> Result<Retained<LAContext>, Error> {
        let context = unsafe { LAContext::new() };
        kind_of(&context)?;
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), Error>>();
        let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
            let result = if success.as_bool() {
                Ok(())
            } else {
                Err(la_error(unsafe { error.as_ref() }.map(|e| e.code()).unwrap_or(0)))
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
            -25300 => Error::Unavailable(Why::KeyGone), // errSecItemNotFound
            -128 => Error::Cancelled,                   // errSecUserCanceled
            -25308 => Error::NotNow,                    // errSecInteractionNotAllowed
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
        let key = SymmetricKey::from_slice(&bytes).map_err(|_| Error::Unavailable(Why::KeyGone));
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
    use super::{Error, Kind, Why};
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
            KeyCredentialStatus::NotFound => Err(Error::Unavailable(Why::KeyGone)),
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

#[cfg(target_os = "android")]
mod imp {
    use std::path::PathBuf;
    use std::sync::{Mutex, TryLockError};
    use std::time::{Duration, Instant};

    use jni::objects::{JByteArray, JValue};
    use twosecret_core::crypto::{sha256, SymmetricKey};
    use zeroize::Zeroizing;

    use super::{Error, Kind, Why};
    use crate::android::{string, with_env};

    // The answers of Biometric (crates/app/android/MainActivity.kt).
    const OK: i32 = 0;
    const CANCELLED: i32 = 1;
    const NOT_NOW: i32 = 2;
    const OFF: i32 = 3;
    const LOCKOUT: i32 = 4;
    const KEY_GONE: i32 = 5;

    /// One prompt at a time: MainActivity keeps one answer.
    static PROMPT: Mutex<()> = Mutex::new(());

    /// Longer than any prompt stays open by itself.
    const PATIENCE: Duration = Duration::from_secs(5 * 60);

    /// The account in file and key names: a hash, so they hold no e-mail
    /// address or other text of the account.
    fn tag(account_id: &str) -> String {
        sha256(account_id.as_bytes())[..16].iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The Android Keystore key that wraps the device key.
    fn alias(account_id: &str) -> String {
        format!("2secret-biometric-{}", tag(account_id))
    }

    /// The wrapped device key: IV and ciphertext, in the app's no-backup
    /// storage next to the profile.
    fn file(account_id: &str) -> PathBuf {
        crate::platform::data_dir().join(format!("biometric-{}.key", tag(account_id)))
    }

    pub fn available() -> Option<Kind> {
        let yes = with_env(|env, activity| env.call_method(activity, "biometricAvailable", "()Z", &[])?.z());
        yes.ok().filter(|y| *y).map(|_| Kind::AndroidBiometric)
    }

    /// The reason as the prompt's subtitle: a sentence ("Unlock your vault").
    fn sentence(reason: &str) -> String {
        let mut chars = reason.trim().chars();
        chars.next().map(|c| c.to_uppercase().chain(chars).collect()).unwrap_or_default()
    }

    /// Show the system's prompt for the key `alias` and let it encrypt
    /// (`create`) or decrypt `input`. Blocks until the prompt closes.
    fn prompt(alias: &str, create: bool, input: &[u8], reason: &str) -> Answer {
        let _one = match PROMPT.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(e)) => e.into_inner(),
            Err(TryLockError::WouldBlock) => return Err(Error::NotNow),
        };
        with_env(|env, activity| {
            let alias = env.new_string(alias)?;
            let input = env.byte_array_from_slice(input)?;
            let reason = env.new_string(sentence(reason))?;
            env.call_method(
                activity,
                "biometricStart",
                "(Ljava/lang/String;Z[BLjava/lang/String;)V",
                &[JValue::Object(&alias), JValue::Bool(create.into()), JValue::Object(&input), JValue::Object(&reason)],
            )?;
            Ok(())
        })
        .map_err(|e| Error::Failed(format!("Android: {e}")))?;
        // Biometric (MainActivity.kt) sets MainActivity.bioDone when the prompt has closed.
        let started = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(150));
            match answer() {
                Ok(Some(result)) => return result,
                Ok(None) if started.elapsed() < PATIENCE => {}
                Ok(None) => {
                    let _ =
                        with_env(|env, activity| env.call_method(activity, "biometricCancel", "()V", &[]).map(|_| ()));
                    return Err(Error::Cancelled);
                }
                Err(e) => return Err(Error::Failed(format!("Android: {e}"))),
            }
        }
    }

    /// What the key's cipher made, or why it made nothing.
    type Answer = Result<Zeroizing<Vec<u8>>, Error>;

    /// The prompt's answer, once it has closed. The output is wiped in Java
    /// once Rust has its copy.
    fn answer() -> Result<Option<Answer>, String> {
        with_env(|env, activity| {
            let class = env.get_object_class(activity)?;
            if !env.get_static_field(&class, "bioDone", "Z")?.z()? {
                return Ok(None);
            }
            let code = env.get_static_field(&class, "bioError", "I")?.i()?;
            let message = env.get_static_field(&class, "bioMessage", "Ljava/lang/String;")?.l()?;
            let message = if message.is_null() { String::new() } else { string(env, message)? };
            let output = env.get_static_field(&class, "bioOutput", "[B")?.l()?;
            let output = if output.is_null() {
                None
            } else {
                let array = JByteArray::from(output);
                let bytes = Zeroizing::new(env.convert_byte_array(&array)?);
                env.set_byte_array_region(&array, 0, &vec![0i8; bytes.len()])?;
                Some(bytes)
            };
            Ok(Some(match (code, output) {
                (OK, Some(bytes)) => Ok(bytes),
                (OK, None) => Err(Error::Failed("no answer from the prompt".into())),
                (CANCELLED, _) => Err(Error::Cancelled),
                (NOT_NOW, _) => Err(Error::NotNow),
                (OFF, _) => Err(Error::Unavailable(Why::Off)),
                (LOCKOUT, _) => Err(Error::Unavailable(Why::Lockout)),
                (KEY_GONE, _) => Err(Error::Unavailable(Why::KeyGone)),
                _ if message.is_empty() => Err(Error::Failed(format!("biometric prompt ({code})"))),
                _ => Err(Error::Failed(message)),
            }))
        })
    }

    pub fn create_device_key(account_id: &str, reason: &str) -> Result<SymmetricKey, Error> {
        let key = SymmetricKey::generate();
        // A new Keystore key; its cipher encrypts the device key.
        let sealed = prompt(&alias(account_id), true, key.as_bytes(), reason)?;
        let path = file(account_id);
        let tmp = path.with_extension("key.tmp");
        let written = std::fs::create_dir_all(crate::platform::data_dir())
            .and_then(|()| std::fs::write(&tmp, &*sealed))
            .and_then(|()| std::fs::rename(&tmp, &path));
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            delete_device_key(account_id);
            return Err(Error::Failed(format!("cannot store the key: {e}")));
        }
        Ok(key)
    }

    pub fn device_key(account_id: &str, reason: &str) -> Result<SymmetricKey, Error> {
        let sealed = match std::fs::read(file(account_id)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::Unavailable(Why::KeyGone)),
            Err(e) => return Err(Error::Failed(format!("cannot read the key: {e}"))),
        };
        let bytes = prompt(&alias(account_id), false, &sealed, reason)?;
        SymmetricKey::from_slice(&bytes).map_err(|_| Error::Unavailable(Why::KeyGone))
    }

    pub fn delete_device_key(account_id: &str) {
        let _ = std::fs::remove_file(file(account_id));
        let _ = with_env(|env, activity| {
            let alias = env.new_string(alias(account_id))?;
            env.call_method(activity, "biometricDelete", "(Ljava/lang/String;)V", &[JValue::Object(&alias)]).map(|_| ())
        });
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios", windows, target_os = "android")))]
mod imp {
    use super::{Error, Kind, Why};
    use twosecret_core::crypto::SymmetricKey;

    pub fn available() -> Option<Kind> {
        None
    }

    pub fn create_device_key(_account_id: &str, _reason: &str) -> Result<SymmetricKey, Error> {
        Err(Error::Unavailable(Why::Off))
    }

    pub fn device_key(_account_id: &str, _reason: &str) -> Result<SymmetricKey, Error> {
        Err(Error::Unavailable(Why::Off))
    }

    pub fn delete_device_key(_account_id: &str) {}
}
