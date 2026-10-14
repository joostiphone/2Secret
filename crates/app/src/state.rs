//! Global application state and the actions that change it.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use twosecret_client::SessionAccess;
use twosecret_core::biometric::BiometricUnlock;
use twosecret_core::crypto::SecretKey;
use twosecret_core::generator::GeneratorOptions;
use twosecret_core::item::{Category, Item};
use twosecret_core::profile::{DeviceSecrets, Profile, DEVICE_KEY, PROFILE_KEY};
use twosecret_core::session::Session;
use twosecret_core::util::now;
use twosecret_core::watchtower::IssueKind;

use crate::biometric;
use crate::extension;
use crate::i18n::{t, Lang, LANG};
use crate::platform;

const PREFS_KEY: &str = "prefs";

#[derive(Clone, PartialEq, Debug)]
pub enum Phase {
    Loading,
    Welcome,
    Create,
    SignIn,
    /// Account just created: show the Secret Key / Emergency Kit.
    NewAccount {
        secret_key: String,
    },
    Locked,
    Unlocked,
}

#[derive(Clone, PartialEq, Debug)]
pub enum Nav {
    All,
    Favorites,
    Category(Category),
    Vault(String),
    Tag(String),
    Trash,
    Watchtower(Option<IssueKind>),
    Generator,
    Settings,
}

impl Nav {
    pub fn is_page(&self) -> bool {
        matches!(self, Nav::Watchtower(_) | Nav::Generator | Nav::Settings)
    }
}

/// Which pane is visible on narrow (phone) screens.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Pane {
    Nav,
    List,
    Detail,
}

/// An item being created or edited.
#[derive(Clone, PartialEq, Debug)]
pub struct Draft {
    pub item: Item,
    pub vault_id: String,
    pub is_new: bool,
}

#[derive(Clone, PartialEq, Debug)]
pub struct Toast {
    pub id: u64,
    pub text: String,
    pub error: bool,
}

#[derive(Clone, Default, PartialEq, Debug)]
pub struct SyncStatus {
    pub running: bool,
    pub requested: bool,
    pub error: Option<String>,
    pub needs_reauth: bool,
}

#[derive(Clone, PartialEq, Debug)]
pub enum Modal {
    NewItem,
    NewVault,
    EditVault(String),
    ShareVault(String),
    DeleteVault(String),
    MoveItem(String),
    DeleteItem(String),
    Reauth,
    ForgetDevice,
    Backup,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

impl Theme {
    pub fn id(&self) -> &'static str {
        match self {
            Theme::System => "system",
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }
}

/// Non-secret user preferences (stored unencrypted).
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    pub lang: Option<Lang>,
    pub theme: Theme,
    /// Minutes of inactivity before locking; 0 = never.
    pub auto_lock_minutes: u32,
    /// Seconds before copied secrets are cleared; 0 = never.
    pub clipboard_clear_secs: u32,
    pub generator: GeneratorOptions,
    /// Check for (and where possible install) new versions once a day.
    pub auto_update: bool,
    /// When a backup (export) was last made on this device.
    pub last_backup_at: i64,
    /// When the backup reminder was last put off ("Later").
    pub backup_snoozed_at: i64,
    /// Remind about a backup after this many days; 0 = never.
    pub backup_reminder_days: u32,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            lang: None,
            theme: Theme::System,
            auto_lock_minutes: 10,
            clipboard_clear_secs: 90,
            generator: GeneratorOptions::default(),
            auto_update: false,
            last_backup_at: 0,
            backup_snoozed_at: 0,
            backup_reminder_days: 30,
        }
    }
}

pub static PHASE: GlobalSignal<Phase> = Signal::global(|| Phase::Loading);
pub static SESSION: GlobalSignal<Option<Session>> = Signal::global(|| None);
pub static PREFS: GlobalSignal<Prefs> = Signal::global(Prefs::default);
pub static NAV: GlobalSignal<Nav> = Signal::global(|| Nav::All);
pub static SELECTED: GlobalSignal<Option<String>> = Signal::global(|| None);
pub static EDITING: GlobalSignal<Option<Draft>> = Signal::global(|| None);
pub static SEARCH: GlobalSignal<String> = Signal::global(String::new);
/// The search field (for the Ctrl/Cmd+F shortcut).
pub static SEARCH_EL: GlobalSignal<Option<std::rc::Rc<MountedData>>> = Signal::global(|| None);
/// Bumped when the search text is changed programmatically.
pub static SEARCH_RESET: GlobalSignal<u32> = Signal::global(|| 0);
pub static TOAST: GlobalSignal<Option<Toast>> = Signal::global(|| None);
pub static SYNC: GlobalSignal<SyncStatus> = Signal::global(SyncStatus::default);
pub static ACTIVITY: GlobalSignal<i64> = Signal::global(now);
pub static MODAL: GlobalSignal<Option<Modal>> = Signal::global(|| None);
pub static BUSY: GlobalSignal<Option<String>> = Signal::global(|| None);
pub static PANE: GlobalSignal<Pane> = Signal::global(|| Pane::List);
/// URL of the active browser tab (extension only).
pub static TAB_URL: GlobalSignal<Option<String>> = Signal::global(|| None);
/// Breach counts from the last Have I Been Pwned check (item id → count).
pub static BREACHES: GlobalSignal<Option<std::collections::HashMap<String, u64>>> = Signal::global(|| None);

/// Extension: the passkey request this window was opened for.
pub static PASSKEY: GlobalSignal<Option<extension::PasskeyRequest>> = Signal::global(|| None);

/// Load preferences and decide the first screen.
pub fn init() {
    let prefs: Prefs = platform::storage()
        .read(PREFS_KEY)
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    *LANG.write() = prefs.lang.unwrap_or_else(|| Lang::from_code(&platform::system_language()));
    *PREFS.write() = prefs;
    let has_account = load_profile().is_some() && device_secrets().is_some();
    if !has_account {
        *PHASE.write() = Phase::Welcome;
        if extension::ENABLED {
            // No 2Secret account yet: leave passkeys to the browser.
            spawn(async move {
                if let Some(request) = extension::pending_passkey().await {
                    extension::answer_passkey(&request.rid, extension::PasskeyAnswer::Fallback).await;
                }
            });
        }
        return;
    }
    if !extension::ENABLED {
        *PHASE.write() = Phase::Locked;
        return;
    }
    // Extension popups are short-lived: reuse an unlock from the last minutes.
    spawn(async move {
        *PASSKEY.write() = extension::pending_passkey().await;
        let profile = load_profile();
        let cached = match &profile {
            Some(p) => extension::cached_unlock(&p.account.id).await,
            None => None,
        };
        match (profile, cached) {
            (Some(p), Some(key)) => match Session::open_with_account_key(p, key) {
                Ok(session) => {
                    *SESSION.write() = Some(session);
                    *PHASE.write() = Phase::Unlocked;
                    touch();
                    request_sync();
                }
                Err(_) => *PHASE.write() = Phase::Locked,
            },
            _ => *PHASE.write() = Phase::Locked,
        }
    });
}

/// Extension: keep the vault unlocked across popup openings until auto-lock.
pub fn remember_unlock() {
    if !extension::ENABLED {
        return;
    }
    let Some((id, key)) = SESSION.peek().as_ref().map(|s| (s.account().id.clone(), s.account_key().clone())) else {
        return;
    };
    let minutes = PREFS.peek().auto_lock_minutes as i64;
    let ttl = if minutes == 0 { 12 * 3600 } else { minutes * 60 };
    dioxus::core::spawn_forever(async move { extension::remember_unlock(&id, &key, ttl).await });
}

thread_local! {
    static LAST_REMEMBER: std::cell::Cell<i64> = const { std::cell::Cell::new(0) };
}

pub fn save_prefs() {
    let json = serde_json::to_string(&*PREFS.read()).unwrap_or_default();
    let _ = platform::storage().write(PREFS_KEY, &json);
}

pub fn set_lang(lang: Lang) {
    *LANG.write() = lang;
    PREFS.write().lang = Some(lang);
    save_prefs();
}

pub fn load_profile() -> Option<Profile> {
    let json = platform::storage().read(PROFILE_KEY).ok().flatten()?;
    Profile::from_json(&json).ok()
}

pub fn device_secrets() -> Option<DeviceSecrets> {
    let json = platform::storage().read(DEVICE_KEY).ok().flatten()?;
    DeviceSecrets::from_json(&json).ok()
}

pub fn secret_key() -> Option<SecretKey> {
    device_secrets().and_then(|d| d.secret_key().ok())
}

/// Store a brand new account on this device and open it.
pub fn adopt_session(session: Session, sk: &SecretKey) -> Result<(), String> {
    let acc = session.account();
    platform::storage()
        .write(DEVICE_KEY, &DeviceSecrets::new(&acc.id, &acc.email, sk).to_json())
        .map_err(|e| e.to_string())?;
    platform::storage().write(PROFILE_KEY, &session.profile().to_json()).map_err(|e| e.to_string())?;
    *SESSION.write() = Some(session);
    *NAV.write() = Nav::All;
    *SELECTED.write() = None;
    touch();
    remember_unlock();
    Ok(())
}

/// Write the (encrypted) profile to storage.
pub fn persist() {
    let json = SESSION.read().as_ref().map(|s| s.profile().to_json());
    if let Some(json) = json {
        if let Err(e) = platform::storage().write(PROFILE_KEY, &json) {
            toast_err(&format!("{}: {e}", t("err.save")));
        }
    }
    refresh_autofill();
}

/// iOS and macOS: give the AutoFill extension the current logins and
/// passkeys. Only while biometric unlock is on: the extension opens them with
/// Face ID or Touch ID, and stops after the same 14 days without the master
/// password.
pub fn refresh_autofill() {
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        let Some(config) = biometric_unlock() else { return };
        let cache = SESSION.peek().as_ref().map(|s| s.autofill_cache(config.password_entered_at));
        if let Some(cache) = cache {
            crate::apple_autofill::write(&cache);
        }
    }
}

pub fn clear_search() {
    if !SEARCH.peek().is_empty() {
        *SEARCH.write() = String::new();
        *SEARCH_RESET.write() += 1;
    }
}

pub fn touch() {
    let ts = now();
    if *ACTIVITY.peek() != ts {
        *ACTIVITY.write() = ts;
    }
    if extension::ENABLED && SESSION.peek().is_some() && ts - LAST_REMEMBER.with(|c| c.get()) > 30 {
        LAST_REMEMBER.with(|c| c.set(ts));
        remember_unlock();
    }
}

pub fn toast(text: &str) {
    show_toast(text, false);
}

pub fn toast_err(text: &str) {
    show_toast(text, true);
}

fn show_toast(text: &str, error: bool) {
    let id = TOAST.peek().as_ref().map(|t| t.id + 1).unwrap_or(1);
    *TOAST.write() = Some(Toast { id, text: text.to_string(), error });
    // `spawn_forever`: the timer must survive the component that showed it.
    dioxus::core::spawn_forever(async move {
        platform::sleep_ms(if error { 6000 } else { 2600 }).await;
        if TOAST.peek().as_ref().map(|t| t.id) == Some(id) {
            *TOAST.write() = None;
        }
    });
}

pub fn busy(text: &str) {
    *BUSY.write() = Some(text.to_string());
}

pub fn unbusy() {
    *BUSY.write() = None;
}

/// Human readable, translated error message.
pub fn core_error(e: &twosecret_core::Error) -> String {
    use twosecret_core::Error as E;
    match e {
        E::WrongPassword => t("err.wrong_password").into(),
        E::InvalidSecretKey(_) => t("err.secret_key").into(),
        E::PermissionDenied(_) => t("err.permission").into(),
        other => other.to_string(),
    }
}

pub fn client_error(e: &twosecret_client::Error) -> String {
    use twosecret_client::Error as E;
    match e {
        E::Core(c) => core_error(c),
        E::Unauthorized => t("err.session_expired").into(),
        E::Network(detail) => format!("{} ({detail})", t("err.network")),
        E::Api { status: 401, .. } => t("err.wrong_credentials").into(),
        E::Api { status: 429, .. } => t("err.rate_limited").into(),
        E::Api { code, .. } if code == "storage_quota" => t("err.storage_quota").into(),
        E::Api { message, .. } => message.clone(),
        E::NotLinked => t("err.not_linked").into(),
        E::Protocol(m) => m.clone(),
    }
}

/// Run a change against the unlocked session, then save and schedule a sync.
pub fn mutate<T>(f: impl FnOnce(&mut Session) -> twosecret_core::Result<T>) -> Option<T> {
    let result = {
        let mut guard = SESSION.write();
        let session = guard.as_mut()?;
        f(session)
    };
    match result {
        Ok(v) => {
            persist();
            request_sync();
            Some(v)
        }
        Err(e) => {
            toast_err(&core_error(&e));
            None
        }
    }
}

/// Lock: forget all decrypted data.
pub fn lock() {
    if extension::ENABLED {
        LAST_REMEMBER.with(|c| c.set(0));
        dioxus::core::spawn_forever(extension::forget_unlock());
    }
    *SESSION.write() = None;
    *EDITING.write() = None;
    *SELECTED.write() = None;
    clear_search();
    *MODAL.write() = None;
    *NAV.write() = Nav::All;
    *BREACHES.write() = None;
    *SYNC.write() = SyncStatus::default();
    *PANE.write() = Pane::List;
    *PHASE.write() = if load_profile().is_some() { Phase::Locked } else { Phase::Welcome };
}

const BIOMETRIC_KEY: &str = "biometric";

fn stored_biometric_unlock() -> Option<BiometricUnlock> {
    let json = platform::storage().read(BIOMETRIC_KEY).ok().flatten()?;
    BiometricUnlock::from_json(&json).ok()
}

/// Biometric unlock settings of the account on this device, if turned on.
pub fn biometric_unlock() -> Option<BiometricUnlock> {
    let config = stored_biometric_unlock()?;
    (config.account_id == load_profile()?.account.id).then_some(config)
}

pub fn save_biometric_unlock(config: &BiometricUnlock) {
    let _ = platform::storage().write(BIOMETRIC_KEY, &config.to_json());
}

/// Turn biometric unlock off and let the operating system forget the key.
pub fn disable_biometric_unlock() {
    if let Some(config) = stored_biometric_unlock() {
        biometric::delete_device_key(&config.account_id);
    }
    let _ = platform::storage().delete(BIOMETRIC_KEY);
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    crate::apple_autofill::clear();
}

/// The master password was just entered: biometric unlock keeps working for
/// another [`BiometricUnlock::MAX_DAYS`] days.
pub fn password_entered() {
    if let Some(mut config) = biometric_unlock() {
        config.password_entered();
        save_biometric_unlock(&config);
        refresh_autofill();
    }
}

/// "{kind}" in a translated text replaced by the biometric method's name.
pub fn with_kind(text: &str, kind: biometric::Kind) -> String {
    text.replace("{kind}", kind.label())
}

/// Remove the account from this device.
pub fn forget_device() {
    disable_biometric_unlock();
    let _ = platform::storage().delete(PROFILE_KEY);
    let _ = platform::storage().delete(DEVICE_KEY);
    lock();
    *PHASE.write() = Phase::Welcome;
}

/// Days between "Later" and the next backup reminder.
const BACKUP_SNOOZE_DAYS: i64 = 7;

/// Whether to remind about making a backup now.
pub fn backup_due(prefs: &Prefs, has_items: bool) -> bool {
    let ts = now();
    has_items
        && prefs.backup_reminder_days > 0
        && ts - prefs.last_backup_at >= prefs.backup_reminder_days as i64 * 86_400
        && ts - prefs.backup_snoozed_at >= BACKUP_SNOOZE_DAYS * 86_400
}

/// Save a backup of all vaults: encrypted with `password`, or, for `json`
/// and `csv`, readable. Returns where it went.
pub async fn save_backup(format: &str, password: String) -> Result<String, String> {
    let Some(data) = SESSION.peek().as_ref().map(|s| s.export(None, false)) else {
        return Err(t("err.no_account").into());
    };
    busy(t("busy.exporting"));
    let date = twosecret_core::util::format_date(now());
    let (name, mime, content) = match format {
        "json" => (format!("2Secret-export-{date}.json"), "application/json", Ok(data.to_json())),
        "csv" => (format!("2Secret-export-{date}.csv"), "text/csv", data.to_csv().map_err(|e| e.to_string())),
        _ => {
            let r = platform::run_heavy(move || data.to_encrypted(&password).map_err(|e| e.to_string())).await;
            (format!("2Secret-backup-{date}.json"), "application/json", r)
        }
    };
    let result = match content {
        Ok(c) => platform::save_file(&name, mime, c.as_bytes()).await,
        Err(e) => Err(e),
    };
    unbusy();
    if result.is_ok() {
        PREFS.write().last_backup_at = now();
        save_prefs();
    }
    result
}

/// Copy a value and clear the clipboard later.
pub fn copy(value: String, what: &str) {
    let what = what.to_string();
    let clear_after = PREFS.peek().clipboard_clear_secs;
    dioxus::core::spawn_forever(async move {
        if platform::copy_text(&value).await {
            toast(&format!("{} {}", what, t("toast.copied")));
            if clear_after > 0 {
                platform::sleep_ms(clear_after as u64 * 1000).await;
                platform::clear_clipboard_if(&value).await;
            }
        } else {
            toast_err(t("err.clipboard"));
        }
        let mut v = value;
        zeroize::Zeroize::zeroize(&mut v);
    });
}

pub fn request_sync() {
    if SESSION.peek().as_ref().is_some_and(|s| s.server().is_some()) {
        SYNC.write().requested = true;
    }
}

struct GlobalSession;

impl SessionAccess for GlobalSession {
    fn with_session<R>(&mut self, f: impl FnOnce(&mut Session) -> R) -> twosecret_client::Result<R> {
        let mut guard = SESSION.write();
        match guard.as_mut() {
            Some(s) => Ok(f(s)),
            None => Err(twosecret_client::Error::Protocol("locked".into())),
        }
    }
}

/// Synchronise with the server (no-op for local accounts).
pub async fn run_sync(show_result: bool) {
    let linked = SESSION.peek().as_ref().map(|s| s.server().is_some() && s.server_token().is_some());
    match linked {
        Some(true) => {}
        Some(false) => {
            if show_result && SESSION.peek().as_ref().is_some_and(|s| s.server().is_some()) {
                SYNC.write().needs_reauth = true;
                *MODAL.write() = Some(Modal::Reauth);
            }
            return;
        }
        None => return,
    }
    if SYNC.peek().running || BUSY.peek().is_some() {
        return;
    }
    {
        let mut s = SYNC.write();
        s.running = true;
        s.requested = false;
    }
    let result = twosecret_client::sync_with(&mut GlobalSession).await;
    let mut status = SYNC.write();
    status.running = false;
    match result {
        Ok(report) => {
            status.error =
                (report.over_quota > 0).then(|| t("sync.over_quota").replace("{n}", &report.over_quota.to_string()));
            status.needs_reauth = false;
            drop(status);
            persist();
            // The selected item may have been deleted remotely.
            let gone = SELECTED
                .peek()
                .as_ref()
                .is_some_and(|id| SESSION.peek().as_ref().is_some_and(|s| s.item(id).is_none()));
            if gone && EDITING.peek().is_none() {
                *SELECTED.write() = None;
            }
            if show_result && report.over_quota > 0 {
                toast_err(&t("sync.over_quota").replace("{n}", &report.over_quota.to_string()));
            } else if show_result {
                toast(&format!("{} ↑{} ↓{}", t("toast.synced"), report.uploaded, report.downloaded + report.deleted));
            }
        }
        Err(twosecret_client::Error::Protocol(m)) if m == "locked" => {}
        Err(e) => {
            let unauthorized = matches!(e, twosecret_client::Error::Unauthorized);
            status.error = Some(client_error(&e));
            status.needs_reauth = unauthorized;
            drop(status);
            if show_result {
                toast_err(&client_error(&e));
            }
        }
    }
}

/// Work on an independent copy of the session for multi-step server
/// operations, then install the result. The UI is blocked meanwhile.
pub fn session_copy() -> Option<Session> {
    SESSION.peek().as_ref().and_then(|s| s.try_clone().ok())
}

/// Online unlock for linked accounts (handles master password changes made
/// on another device and expired sessions). Runs Argon2id off the UI thread.
pub async fn unlock_online(profile: Profile, password: String) -> Result<Session, String> {
    let sk = secret_key().ok_or_else(|| t("err.no_account").to_string())?;
    let url = profile.server.as_ref().map(|s| s.url.clone()).ok_or_else(|| t("err.not_linked").to_string())?;
    let email = profile.account.email.clone();
    let pre = twosecret_client::prelogin(&url, &email).await.map_err(|e| client_error(&e))?;
    let salt = twosecret_core::util::unb64(&pre.salt).map_err(|e| core_error(&e))?;
    let keys =
        platform::run_heavy(move || twosecret_core::crypto::derive_keys(&password, &sk, &email, &salt, &pre.kdf))
            .await
            .map_err(|e| core_error(&e))?;
    twosecret_client::unlock_online_with_keys(profile, &keys, &platform::device_name()).await.map_err(|e| match e {
        twosecret_client::Error::Api { status: 401, .. } | twosecret_client::Error::Core(_) => {
            t("err.wrong_password").to_string()
        }
        other => client_error(&other),
    })
}

/// Extension: fill the active tab with an item's username, password and
/// current one-time code, then close the popup.
pub fn fill_item(id: &str) {
    let Some((user, pw, code, rules)) = SESSION.peek().as_ref().and_then(|s| s.item(id)).map(|i| {
        let code = i
            .totp_secret()
            .and_then(|t| twosecret_core::totp::Totp::parse(t).ok())
            .map(|t| t.now().0)
            .unwrap_or_default();
        let rules = twosecret_core::util::fill_rules(&i.urls);
        (i.username().unwrap_or("").to_string(), i.password().unwrap_or("").to_string(), code, rules)
    }) else {
        return;
    };
    if rules.is_empty() {
        toast_err(t("ext.wrong_site"));
        return;
    }
    dioxus::core::spawn_forever(async move {
        match extension::fill(&user, &pw, &code, &rules).await {
            extension::FillResult::Filled => {
                if !code.is_empty() && !pw.is_empty() {
                    // The code is usually asked on the next page: keep it ready.
                    platform::copy_text(&code).await;
                }
                extension::close();
            }
            extension::FillResult::WrongSite => toast_err(t("ext.wrong_site")),
            extension::FillResult::NothingToFill => toast_err(t("ext.nothing_to_fill")),
        }
    });
}

pub fn install_session(session: Session) {
    *SESSION.write() = Some(session);
    persist();
}
