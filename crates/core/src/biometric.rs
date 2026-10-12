//! Unlocking with Touch ID, Face ID or Windows Hello.
//!
//! When it is turned on, the account key is encrypted with a random 256-bit
//! *device key*, and the device key is handed to the operating system, which
//! releases it only after a successful biometric check (the keychain on Apple
//! platforms; on Windows the device key is derived from a Windows Hello
//! signature and never stored). This module holds the platform-independent
//! part: the encrypted account key and the rule that the master password is
//! needed again after [`BiometricUnlock::MAX_DAYS`] days.

use serde::{Deserialize, Serialize};

use crate::crypto::{decrypt, encrypt, EncString, SymmetricKey};
use crate::util::now;
use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BiometricUnlock {
    pub account_id: String,
    /// The account key, encrypted with the device key.
    pub wrapped_account_key: EncString,
    /// When the master password was last entered on this device.
    pub password_entered_at: i64,
}

fn aad(account_id: &str) -> Vec<u8> {
    format!("2secret/v1/biometric/{account_id}").into_bytes()
}

impl BiometricUnlock {
    /// Biometric unlock stops working when the master password has not been
    /// entered for this long, so it is not forgotten.
    pub const MAX_DAYS: i64 = 14;

    pub fn new(account_id: &str, account_key: &SymmetricKey, device_key: &SymmetricKey) -> Self {
        Self {
            account_id: account_id.to_string(),
            wrapped_account_key: encrypt(device_key, account_key.as_bytes(), &aad(account_id)),
            password_entered_at: now(),
        }
    }

    /// The account key, if `device_key` is the one released by the
    /// operating system and the master password was entered recently enough.
    pub fn account_key(&self, device_key: &SymmetricKey) -> Result<SymmetricKey> {
        if self.password_required() {
            return Err(Error::invalid("enter your master password"));
        }
        let bytes = decrypt(device_key, &self.wrapped_account_key, &aad(&self.account_id))?;
        SymmetricKey::from_slice(&bytes)
    }

    /// True when the master password has to be entered first.
    pub fn password_required(&self) -> bool {
        let age = now() - self.password_entered_at;
        !(0..Self::MAX_DAYS * 86_400).contains(&age)
    }

    /// The master password was just entered.
    pub fn password_entered(&mut self) {
        self.password_entered_at = now();
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("serialization cannot fail")
    }

    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_key_releases_the_account_key() {
        let (account_key, device_key) = (SymmetricKey::generate(), SymmetricKey::generate());
        let unlock = BiometricUnlock::new("acc", &account_key, &device_key);
        assert_eq!(unlock.account_key(&device_key).unwrap(), account_key);
        assert!(unlock.account_key(&SymmetricKey::generate()).is_err());

        // Bound to the account it was made for.
        let mut other = unlock.clone();
        other.account_id = "other".into();
        assert!(other.account_key(&device_key).is_err());

        let restored = BiometricUnlock::from_json(&unlock.to_json()).unwrap();
        assert_eq!(restored, unlock);
    }

    #[test]
    fn master_password_is_needed_every_two_weeks() {
        let device_key = SymmetricKey::generate();
        let mut unlock = BiometricUnlock::new("acc", &SymmetricKey::generate(), &device_key);
        assert!(!unlock.password_required());
        unlock.password_entered_at -= BiometricUnlock::MAX_DAYS * 86_400 + 1;
        assert!(unlock.password_required());
        assert!(unlock.account_key(&device_key).is_err());
        unlock.password_entered();
        assert!(unlock.account_key(&device_key).is_ok());
        // A clock set back far is not a way around it either.
        unlock.password_entered_at = now() + 86_400;
        assert!(unlock.password_required());
    }
}
