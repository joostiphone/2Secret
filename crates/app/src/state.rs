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
    /// The dashboard: an overview of the vaults.
    Home,
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
        matches!(self, Nav::Home | Nav::Watchtower(_) | Nav::Generator | Nav::Settings)
    }
}

/// What the apps show after unlocking (Settings → Appearance).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartScreen {
    #[default]
    Dashboard,
    All,
    Favorites,
    Watchtower,
}

impl StartScreen {
    pub const ALL: [StartScreen; 4] =
        [StartScreen::Dashboard, StartScreen::All, StartScreen::Favorites, StartScreen::Watchtower];

    pub fn id(&self) -> &'static str {
        match self {
            StartScreen::Dashboard => "dashboard",
            StartScreen::All => "all",
            StartScreen::Favorites => "favorites",
            StartScreen::Watchtower => "watchtower",
        }
    }

    pub fn nav(&self) -> Nav {
        match self {
            StartScreen::Dashboard => Nav::Home,
            StartScreen::All => Nav::All,
            StartScreen::Favorites => Nav::Favorites,
            StartScreen::Watchtower => Nav::Watchtower(None),
        }
    }
}

/// The first screen after unlocking. The browser extension always starts
/// with the list, which suggests the logins for the open website.
pub fn start_nav() -> Nav {
    if extension::ENABLED {
        Nav::All
    } else {
        PREFS.peek().start_screen.nav()
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
    /// Add a one-time password from an `otpauth://` link to a login.
    SetUpCode(String),
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
    /// Fetch the icons of the websites of logins (from those websites).
    pub website_icons: bool,
    /// The profile shown last ([`SLOT`]).
    pub active_profile: usize,
    pub start_screen: StartScreen,
    /// Desktop: the icon in the menu bar or system tray (`tray`); closing the
    /// window then keeps 2Secret running there.
    pub tray: bool,
    /// Desktop: the Quick Access shortcut (`quick`).
    pub quick_access: bool,
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
            website_icons: true,
            active_profile: 0,
            start_screen: StartScreen::default(),
            tray: true,
            quick_access: true,
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

/// A one-time password from an `otpauth://` link (`code_setup`), until the
/// vault is unlocked and its dialog opens.
pub static CODE_SETUP: GlobalSignal<Option<String>> = Signal::global(|| None);

/// Extension: the passkey request this window was opened for.
pub static PASSKEY: GlobalSignal<Option<extension::PasskeyRequest>> = Signal::global(|| None);

/// Load preferences and decide the first screen.
/// Profiles on this device: the apps keep up to two accounts side by side,
/// for example a personal one and one for work on another server, each with
/// its own storage, Secret Key and biometric unlock. Profile 0 uses the
/// storage keys from before there were profiles.
pub const MAX_PROFILES: usize = 2;
/// Not in the web vault, which belongs to its server, nor in the browser
/// extension.
pub const MULTI_PROFILE: bool = cfg!(not(target_arch = "wasm32"));
/// The profile shown.
pub static SLOT: GlobalSignal<usize> = Signal::global(|| 0);
/// The other profile while it stays unlocked in the background, so
/// switching back is instant. Locking locks it too.
pub static PARKED: GlobalSignal<Option<(usize, Session)>> = Signal::global(|| None);

/// The storage key of a profile's `base` record ("profile", "profile-2").
fn slot_key(base: &str, slot: usize) -> String {
    if slot == 0 {
        base.to_string()
    } else {
        format!("{base}-{}", slot + 1)
    }
}

fn active_key(base: &str) -> String {
    slot_key(base, *SLOT.peek())
}

pub fn load_profile_in(slot: usize) -> Option<Profile> {
    let json = platform::storage().read(&slot_key(PROFILE_KEY, slot)).ok().flatten()?;
    Profile::from_json(&json).ok()
}

/// Whether a profile is set up in `slot` (without reading the whole vault).
pub fn profile_exists(slot: usize) -> bool {
    platform::storage().read(&slot_key(DEVICE_KEY, slot)).ok().flatten().is_some()
}

/// The other profile on this device, if there is one.
pub fn other_profile() -> Option<usize> {
    let active = *SLOT.peek();
    (0..MAX_PROFILES).find(|slot| *slot != active && MULTI_PROFILE && profile_exists(*slot))
}

/// A profile as the profile menu and the lock screen show it.
#[derive(Clone, PartialEq, Debug)]
pub struct ProfileEntry {
    pub slot: usize,
    pub name: String,
    pub email: String,
    /// Only known while the profile is unlocked (it is encrypted).
    pub photo: Option<String>,
    pub active: bool,
}

pub fn profiles() -> Vec<ProfileEntry> {
    let active = *SLOT.peek();
    (0..MAX_PROFILES)
        .filter(|slot| (*slot == active || MULTI_PROFILE) && profile_exists(*slot))
        .filter_map(|slot| {
            let (name, email, photo) = if slot == active && SESSION.peek().is_some() {
                let session = SESSION.peek();
                let s = session.as_ref()?;
                (s.account().name.clone(), s.account().email.clone(), s.avatar())
            } else if let Some((_, s)) = PARKED.peek().as_ref().filter(|(p, _)| *p == slot) {
                (s.account().name.clone(), s.account().email.clone(), s.avatar())
            } else {
                let p = load_profile_in(slot)?;
                (p.account.name, p.account.email, None)
            };
            Some(ProfileEntry { slot, name, email, photo, active: slot == active })
        })
        .collect()
}

/// Show another profile: the open one stays unlocked in the background; the
/// other one opens unlocked if it was, else on its lock screen (or, for an
/// empty slot, on the welcome screen to add a profile).
pub fn switch_profile(slot: usize) {
    let current = *SLOT.peek();
    if !MULTI_PROFILE || slot >= MAX_PROFILES || slot == current {
        return;
    }
    let open = SESSION.write().take();
    let parked = PARKED.write().take();
    if let Some(session) = open {
        *PARKED.write() = Some((current, session));
    }
    reset_view();
    *SLOT.write() = slot;
    PREFS.write().active_profile = slot;
    save_prefs();
    match parked {
        Some((s, session)) if s == slot => {
            *SESSION.write() = Some(session);
            *PHASE.write() = Phase::Unlocked;
            touch();
            request_sync();
        }
        _ => {
            crate::components::onboarding::offer_biometric_again();
            *PHASE.write() = if profile_exists(slot) { Phase::Locked } else { Phase::Welcome };
        }
    }
}

/// Start adding a second profile (create an account or sign in).
pub fn add_profile() {
    if let Some(free) = (0..MAX_PROFILES).find(|slot| !profile_exists(*slot)) {
        switch_profile(free);
    }
}

/// Forget what the screen showed of a profile.
fn reset_view() {
    *EDITING.write() = None;
    *SELECTED.write() = None;
    clear_search();
    *MODAL.write() = None;
    *NAV.write() = start_nav();
    *BREACHES.write() = None;
    *SYNC.write() = SyncStatus::default();
    *PANE.write() = Pane::List;
}

/// The stored preferences (the defaults when there are none).
pub fn stored_prefs() -> Prefs {
    platform::storage().read(PREFS_KEY).ok().flatten().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

pub fn init() {
    let prefs = stored_prefs();
    *LANG.write() = prefs.lang.unwrap_or_else(|| Lang::from_code(&platform::system_language()));
    if MULTI_PROFILE {
        let wanted = prefs.active_profile.min(MAX_PROFILES - 1);
        *SLOT.write() = if profile_exists(wanted) {
            wanted
        } else {
            (0..MAX_PROFILES).find(|slot| profile_exists(*slot)).unwrap_or(0)
        };
    }
    *PREFS.write() = prefs;
    *NAV.write() = start_nav();
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

/// The profile shown, as stored (locked).
pub fn load_profile() -> Option<Profile> {
    load_profile_in(*SLOT.peek())
}

/// Store the profile shown.
pub fn save_profile(profile: &Profile) -> Result<(), String> {
    platform::storage().write(&active_key(PROFILE_KEY), &profile.to_json()).map_err(|e| e.to_string())
}

pub fn device_secrets() -> Option<DeviceSecrets> {
    let json = platform::storage().read(&active_key(DEVICE_KEY)).ok().flatten()?;
    DeviceSecrets::from_json(&json).ok()
}

pub fn secret_key() -> Option<SecretKey> {
    device_secrets().and_then(|d| d.secret_key().ok())
}

/// Store a brand new account on this device and open it.
pub fn adopt_session(session: Session, sk: &SecretKey) -> Result<(), String> {
    let acc = session.account();
    // The same e-mail address on two servers is fine; the same account twice is not.
    if other_profile().and_then(load_profile_in).is_some_and(|p| p.account.id == acc.id) {
        return Err(t("profiles.already_here").to_string());
    }
    platform::storage()
        .write(&active_key(DEVICE_KEY), &DeviceSecrets::new(&acc.id, &acc.email, sk).to_json())
        .map_err(|e| e.to_string())?;
    save_profile(session.profile())?;
    *SESSION.write() = Some(session);
    *NAV.write() = start_nav();
    *SELECTED.write() = None;
    touch();
    remember_unlock();
    Ok(())
}

/// Write the (encrypted) profile to storage.
pub fn persist() {
    let json = SESSION.read().as_ref().map(|s| s.profile().to_json());
    if let Some(json) = json {
        if let Err(e) = platform::storage().write(&active_key(PROFILE_KEY), &json) {
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

/// Whether this app fetches website icons: not in the browser, where websites
/// do not let other pages read their icons.
pub const FETCHES_ICONS: bool = cfg!(not(target_arch = "wasm32"));

/// Fetch website icons for these items, one website after the other, if they
/// have a public website without an icon for it (and the setting is on).
/// Each icon is saved, encrypted, with its item; other devices get it
/// through sync.
pub fn fetch_icons(ids: Vec<String>) {
    #[cfg(not(target_arch = "wasm32"))]
    {
        if !PREFS.peek().website_icons {
            return;
        }
        let wanted: Vec<(String, String)> = {
            let session = SESSION.peek();
            let Some(session) = session.as_ref() else { return };
            ids.into_iter()
                .filter_map(|id| {
                    let item = session.item(&id)?;
                    let writable =
                        session.item_vault(&id).and_then(|v| session.vault(v)).is_some_and(|v| v.role.can_write());
                    if !writable || item.is_trashed() || !twosecret_core::favicon::wants_icon(item) {
                        return None;
                    }
                    Some((id, twosecret_core::favicon::icon_host(item)?))
                })
                .collect()
        };
        if wanted.is_empty() {
            return;
        }
        spawn(async move {
            let mut unsaved = 0;
            let total = wanted.len();
            for (i, (id, host)) in wanted.into_iter().enumerate() {
                if let Some(icon) = twosecret_client::favicon::fetch(&host).await {
                    let saved = SESSION.write().as_mut().map(|s| s.set_icon(&id, icon));
                    if matches!(saved, Some(Ok(()))) {
                        unsaved += 1;
                    }
                }
                // Save now and then, not after every icon of a long list.
                if unsaved > 0 && (unsaved >= 20 || i + 1 == total) {
                    unsaved = 0;
                    persist();
                    request_sync();
                }
            }
        });
    }
    #[cfg(target_arch = "wasm32")]
    let _ = ids;
}

/// Show an item from outside the list (the dashboard, a dialog).
pub fn open_item(id: &str) {
    clear_search();
    *NAV.write() = Nav::All;
    *EDITING.write() = None;
    *SELECTED.write() = Some(id.to_string());
    *PANE.write() = Pane::Detail;
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
    // Locking locks every profile.
    *PARKED.write() = None;
    reset_view();
    *PHASE.write() = if load_profile().is_some() { Phase::Locked } else { Phase::Welcome };
}

const BIOMETRIC_KEY: &str = "biometric";

fn stored_biometric_unlock() -> Option<BiometricUnlock> {
    let json = platform::storage().read(&active_key(BIOMETRIC_KEY)).ok().flatten()?;
    BiometricUnlock::from_json(&json).ok()
}

/// Biometric unlock settings of the account on this device, if turned on.
pub fn biometric_unlock() -> Option<BiometricUnlock> {
    let config = stored_biometric_unlock()?;
    (config.account_id == load_profile()?.account.id).then_some(config)
}

pub fn save_biometric_unlock(config: &BiometricUnlock) {
    let _ = platform::storage().write(&active_key(BIOMETRIC_KEY), &config.to_json());
}

/// Turn biometric unlock off and let the operating system forget the key.
pub fn disable_biometric_unlock() {
    if let Some(config) = stored_biometric_unlock() {
        biometric::delete_device_key(&config.account_id);
    }
    let _ = platform::storage().delete(&active_key(BIOMETRIC_KEY));
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

/// Remove the profile shown from this device; the other one, if any, stays.
pub fn forget_device() {
    disable_biometric_unlock();
    let _ = platform::storage().delete(&active_key(PROFILE_KEY));
    let _ = platform::storage().delete(&active_key(DEVICE_KEY));
    *SESSION.write() = None;
    reset_view();
    match other_profile() {
        Some(other) => {
            // Keep the other profile as it was (unlocked or not).
            let parked = PARKED.write().take();
            *SLOT.write() = other;
            PREFS.write().active_profile = other;
            save_prefs();
            match parked {
                Some((slot, session)) if slot == other => {
                    *SESSION.write() = Some(session);
                    *PHASE.write() = Phase::Unlocked;
                }
                _ => *PHASE.write() = Phase::Locked,
            }
        }
        None => {
            lock();
            *PHASE.write() = Phase::Welcome;
        }
    }
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

/// The open session for a sync, bound to its account: after a switch to
/// the other profile (or locking) the sync stops instead of touching it.
struct GlobalSession {
    account_id: String,
}

impl SessionAccess for GlobalSession {
    fn with_session<R>(&mut self, f: impl FnOnce(&mut Session) -> R) -> twosecret_client::Result<R> {
        let mut guard = SESSION.write();
        match guard.as_mut() {
            Some(s) if s.account().id == self.account_id => Ok(f(s)),
            _ => Err(twosecret_client::Error::Protocol("locked".into())),
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
    let Some(account_id) = SESSION.peek().as_ref().map(|s| s.account().id.clone()) else {
        SYNC.write().running = false;
        return;
    };
    let result = twosecret_client::sync_with(&mut GlobalSession { account_id: account_id.clone() }).await;
    // Switched to the other profile meanwhile: its status is not ours.
    if SESSION.peek().as_ref().is_none_or(|s| s.account().id != account_id) {
        SYNC.write().running = false;
        return;
    }
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
    // Only over the same account (the other profile may be shown by now).
    if SESSION.peek().as_ref().is_some_and(|s| s.account().id != session.account().id) {
        return;
    }
    *SESSION.write() = Some(session);
    persist();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_screen_preference() {
        // Preferences from before the dashboard open it.
        let old: Prefs = serde_json::from_str(r#"{"theme":"dark","auto_lock_minutes":5}"#).unwrap();
        assert_eq!(old.start_screen, StartScreen::Dashboard);
        assert_eq!(old.start_screen.nav(), Nav::Home);
        assert!(old.tray);
        assert!(old.quick_access);
        for start in StartScreen::ALL {
            let json = serde_json::to_string(&Prefs { start_screen: start, ..Prefs::default() }).unwrap();
            assert!(json.contains(&format!("\"start_screen\":\"{}\"", start.id())));
            assert_eq!(serde_json::from_str::<Prefs>(&json).unwrap().start_screen, start);
        }
    }

    #[test]
    fn profile_storage_keys() {
        // The first profile keeps the keys from before there were profiles.
        assert_eq!(slot_key(PROFILE_KEY, 0), PROFILE_KEY);
        assert_eq!(slot_key(DEVICE_KEY, 1), format!("{DEVICE_KEY}-2"));
        assert_eq!(slot_key(BIOMETRIC_KEY, 1), "biometric-2");
        // Valid file names for the native storage.
        let dir = std::env::temp_dir().join(format!("2secret-slots-{}", std::process::id()));
        let storage = twosecret_core::storage::FileStorage::new(&dir).unwrap();
        use twosecret_core::storage::Storage;
        storage.write(&slot_key(PROFILE_KEY, 1), "{}").unwrap();
        assert_eq!(storage.read(&slot_key(PROFILE_KEY, 1)).unwrap().as_deref(), Some("{}"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
