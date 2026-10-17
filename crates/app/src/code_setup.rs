//! Setting up one-time passwords from `otpauth://` links. iOS and macOS open
//! 2Secret with them when it is chosen under *Set Up Codes In* (Settings →
//! General → AutoFill & Passwords), for example after tapping a website's
//! setup link or scanning its QR code with the camera; on Windows, Linux and
//! the BSDs `link_handler` registers 2Secret for them. The event loop (or
//! `link_handler`) hands the link to the UI, which asks which login gets it
//! once the vault is unlocked (`Modal::SetUpCode`).

use twosecret_core::item::Item;
use twosecret_core::totp::Totp;

#[cfg(any(feature = "desktop", feature = "mobile"))]
static OPENED: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
#[cfg(any(feature = "desktop", feature = "mobile"))]
static NOTIFY: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// From the event loop: the app was opened with these URLs (before the UI
/// runs, when the link launched the app).
#[cfg(any(feature = "desktop", feature = "mobile"))]
pub fn opened<'a>(urls: impl IntoIterator<Item = &'a str>) {
    let Some(link) =
        urls.into_iter().filter(|u| u.get(..10).is_some_and(|s| s.eq_ignore_ascii_case("otpauth://"))).last()
    else {
        return;
    };
    if let Ok(mut opened) = OPENED.lock() {
        *opened = Some(link.to_string());
    }
    NOTIFY.notify_one();
}

/// In the UI: wait for links and keep the latest in
/// [`CODE_SETUP`](crate::state::CODE_SETUP).
pub async fn receive() {
    #[cfg(any(feature = "desktop", feature = "mobile"))]
    loop {
        NOTIFY.notified().await;
        let Some(link) = OPENED.lock().ok().and_then(|mut o| o.take()) else { continue };
        match Totp::parse(&link) {
            Ok(totp) => *crate::state::CODE_SETUP.write() = Some(totp.to_uri()),
            Err(_) => crate::state::toast_err(crate::i18n::t("code.invalid")),
        }
        // The link may come from a browser in front of the app, which may be
        // hidden in the system tray.
        #[cfg(feature = "desktop")]
        crate::tray::show();
    }
}

/// How well an item fits the account a one-time password is for: its title
/// or website names the issuer, and it has the account's user name.
pub fn fit(item: &Item, totp: &Totp) -> u8 {
    let squash = |s: &str| s.to_lowercase().replace(' ', "");
    let issuer = totp.issuer.as_deref().map(squash).filter(|i| !i.is_empty());
    let named = issuer
        .is_some_and(|i| squash(&item.title).contains(&i) || item.urls.iter().any(|u| u.to_lowercase().contains(&i)));
    let account = totp.account.as_deref().map(str::to_lowercase);
    let same_user = account.is_some_and(|a| item.username().is_some_and(|u| u.to_lowercase() == a));
    u8::from(named) * 2 + u8::from(same_user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_prefers_the_issuer() {
        let totp = Totp::parse("otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub").unwrap();
        let github = Item::login("GitHub", "octo", "pw", Some("https://github.com"));
        let other_github = Item::login("Work", "someone", "pw", Some("https://github.com/login"));
        let same_user = Item::login("Forum", "octo", "pw", Some("https://forum.example"));
        let unrelated = Item::login("Bank", "me", "pw", Some("https://bank.example"));
        assert_eq!(fit(&github, &totp), 3);
        assert_eq!(fit(&other_github, &totp), 2);
        assert_eq!(fit(&same_user, &totp), 1);
        assert_eq!(fit(&unrelated, &totp), 0);
    }
}
