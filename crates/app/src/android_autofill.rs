//! Android: 2Secret fills logins in other apps and browsers through the
//! system's AutoFill (crates/app/android/AutofillService.kt).
//!
//! While the vault is unlocked, biometric unlock is on and 2Secret is the
//! phone's AutoFill service, the app hands the service its logins
//! ([`AndroidAutofill`]) through a file in the app's no-backup storage. The
//! file is encrypted with AES-256-GCM under a new random key on every write;
//! that key is encrypted (RSA-OAEP) with an Android Keystore key pair whose
//! private key only works after a strong fingerprint or face check and is
//! deleted for good when the enrolled fingerprints or faces change
//! (AutofillStore in crates/app/android/MainActivity.kt). Encrypting needs no check, so the
//! app can write without asking; reading needs one, so nothing of the file
//! reaches the service before the person confirms.

use jni::objects::JValue;
use twosecret_core::autofill::AndroidAutofill;
use zeroize::Zeroizing;

use crate::android::with_env;

fn ask(method: &str) -> bool {
    with_env(|env, activity| env.call_method(activity, method, "()Z", &[])?.z()).unwrap_or(false)
}

/// Whether the phone can fill with 2Secret: Android 9 or newer (for the
/// fingerprint or face check) with AutoFill.
pub fn available() -> bool {
    ask("autofillAvailable")
}

/// Whether 2Secret is the phone's AutoFill service.
pub fn active() -> bool {
    ask("autofillActive")
}

/// Open Android's screen to choose 2Secret as the AutoFill service. False
/// when the phone has none.
pub fn open_settings() -> bool {
    ask("autofillSettings")
}

/// Hand the service a new store. Encrypting and writing happen on a
/// background thread of the app, in the order they were asked for.
pub fn write(store: &AndroidAutofill) {
    let Ok(json) = serde_json::to_vec(store) else { return };
    let json = Zeroizing::new(json);
    let result = with_env(|env, activity| {
        // Java wipes its copy once it is encrypted.
        let bytes = env.byte_array_from_slice(&json)?;
        env.call_method(activity, "autofillWrite", "([B)V", &[JValue::Object(&bytes)]).map(|_| ())
    });
    if let Err(e) = result {
        eprintln!("2Secret: AutoFill is not available: {e}");
    }
}

/// Remove the store and its Keystore key (AutoFill stops filling).
pub fn clear() {
    let _ = with_env(|env, activity| env.call_method(activity, "autofillClear", "()V", &[]).map(|_| ()));
}
