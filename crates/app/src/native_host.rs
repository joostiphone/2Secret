//! Desktop: the browser connection (*Settings → Desktop app → Browser
//! connection*). The 2Secret browser extension reaches the app through a
//! native messaging host: a program the browser starts and talks to on its
//! stdin and stdout. That program is 2Secret itself, started with the
//! arguments a browser passes ([`main_if_host`]); the loop lives in
//! `twosecret_agent::host`. This module registers the host with every
//! browser the user has (a manifest file per browser, or a registry value on
//! Windows) and checks, for `agent_access`, that a connection claiming to be
//! a browser really comes from this program.

use std::path::{Path, PathBuf};

use dioxus::prelude::*;
use twosecret_agent::host::{self, HostOptions};
use twosecret_agent::native_host::{self as nm, Browser, HostArgs, Location, Os, Place, KNOWN_EXTENSION_IDS};

use crate::i18n::t;
use crate::icons::either;
use crate::platform;
use crate::state::*;

/// When a browser started this program as its native messaging host: run
/// the host and return the exit code. Called before anything else in
/// `run()`, because the host owns stdin and stdout.
pub fn main_if_host() -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let host_args = nm::from_args(&args)?;
    let browser = match &host_args {
        HostArgs::Firefox { .. } => Some("firefox".to_string()),
        HostArgs::Manual { browser } => browser.clone(),
        HostArgs::Chromium { .. } => parent_browser(),
    };
    let opts = HostOptions {
        home: platform::data_dir(),
        browser,
        extension: host_args.extension(),
        exit_marker: crate::updater::update_marker(),
        exit_when_gone: true,
    };
    Some(host::run(std::io::stdin(), std::io::stdout(), opts))
}

/// The browser that started us, from the parent process (Chromium browsers
/// all pass the same kind of arguments). On Windows Chrome starts hosts
/// through `cmd.exe`, so the grandparent counts there.
fn parent_browser() -> Option<String> {
    #[cfg(windows)]
    {
        let mut pid = crate::agent_access::os::parent_pid(std::process::id())?;
        for _ in 0..3 {
            let image = crate::agent_access::os::image_path(pid)?;
            let name = image.rsplit(['/', '\\']).next().unwrap_or(&image).to_lowercase();
            if name == "cmd.exe" || name == "conhost.exe" {
                pid = crate::agent_access::os::parent_pid(pid)?;
                continue;
            }
            return nm::browser_from_parent(&image).map(str::to_string);
        }
        None
    }
    #[cfg(not(windows))]
    {
        nm::browser_from_parent(&twosecret_agent::parent_process_name()?).map(str::to_string)
    }
}

/// The program a browser should start: the AppImage itself on Linux (the
/// mounted copy disappears), else this executable.
pub fn program_path() -> Option<PathBuf> {
    std::env::var_os("APPIMAGE").map(PathBuf::from).filter(|p| p.is_file()).or_else(|| std::env::current_exe().ok())
}

/// Whether the program on the other end of a connection is this program:
/// the same file name and size (not the same path: an AppImage is mounted
/// somewhere else at every start). Only such a connection may act as a
/// browser, because browsers receive the logins that agents may fill.
pub fn same_program(peer_exe: Option<&str>) -> bool {
    let Some(peer) = peer_exe else { return false };
    let Ok(me) = std::env::current_exe() else { return false };
    same_file(Path::new(peer), &me)
}

fn same_file(a: &Path, b: &Path) -> bool {
    if a.file_name().is_none() || a.file_name() != b.file_name() {
        return false;
    }
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.is_file() && b.is_file() && a.len() == b.len(),
        _ => false,
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).filter(|h| !h.is_empty()).map(PathBuf::from)
}

fn config_dir(home: &Path) -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"))
}

fn locations() -> Vec<Location> {
    let (Some(os), Some(home)) = (Os::current(), home_dir()) else { return Vec::new() };
    let config = config_dir(&home);
    nm::locations(os, &home, &config)
}

/// Whether the browser of a location seems to be on this computer: its
/// own folder (or registry key) exists. Nothing is written for the others.
fn browser_present(location: &Location) -> bool {
    match &location.place {
        Place::Dir(dir) => dir.parent().is_some_and(Path::exists),
        Place::Registry(key) => os::key_exists(key.rsplit_once('\\').map(|(vendor, _)| vendor).unwrap_or(key)),
    }
}

/// On Windows the manifests live in the data directory; the registry points at them.
fn windows_manifest_path(browser: Browser) -> PathBuf {
    platform::data_dir().join("native-host").join(format!("{}.{}.json", nm::HOST_NAME, browser.name()))
}

fn registered(location: &Location) -> bool {
    match &location.place {
        Place::Dir(_) => location.manifest_path().is_some_and(|p| p.is_file()),
        Place::Registry(key) => os::default_value(key).is_some_and(|p| Path::new(&p).is_file()),
    }
}

/// Which browsers are set up (true) or present but not set up (false).
pub fn status() -> Vec<(Browser, bool)> {
    locations().iter().filter(|l| browser_present(l) || registered(l)).map(|l| (l.browser, registered(l))).collect()
}

fn write_if_changed(path: &Path, text: &str) -> bool {
    if std::fs::read_to_string(path).ok().as_deref() == Some(text) {
        return true;
    }
    if let Some(dir) = path.parent() {
        if std::fs::create_dir_all(dir).is_err() {
            return false;
        }
    }
    std::fs::write(path, text).is_ok()
}

/// Write the manifest for every browser on this computer, allowing the
/// store extension and the user's own (development) extension ids.
pub fn register(dev_ids: &[String]) -> bool {
    let Some(exe) = program_path() else { return false };
    let origins = nm::origins(KNOWN_EXTENSION_IDS, dev_ids);
    let mut ok = true;
    let mut any = false;
    for location in locations() {
        if !browser_present(&location) {
            continue;
        }
        any = true;
        let text = if location.browser.is_firefox() {
            nm::firefox_manifest(&exe)
        } else {
            nm::chromium_manifest(&exe, &origins)
        };
        let written = match &location.place {
            Place::Dir(_) => location.manifest_path().is_some_and(|p| write_if_changed(&p, &text)),
            Place::Registry(key) => {
                let path = windows_manifest_path(location.browser);
                write_if_changed(&path, &text) && os::set_default_value(key, &path.to_string_lossy())
            }
        };
        ok &= written;
    }
    ok && any
}

/// Remove every manifest (and registry key) again.
pub fn unregister() -> bool {
    let mut ok = true;
    for location in locations() {
        match &location.place {
            Place::Dir(_) => {
                if let Some(path) = location.manifest_path() {
                    if path.exists() {
                        ok &= std::fs::remove_file(&path).is_ok();
                    }
                }
            }
            Place::Registry(key) => {
                if os::default_value(key).is_some() {
                    ok &= os::delete_key(key);
                }
                let path = windows_manifest_path(location.browser);
                if path.exists() {
                    ok &= std::fs::remove_file(&path).is_ok();
                }
            }
        }
    }
    ok
}

/// At start: point the manifests at this copy of 2Secret, which may have
/// moved or been updated, and cover browsers installed since.
pub fn refresh() {
    let prefs = stored_prefs();
    if prefs.browser_host {
        register(&prefs.extension_ids);
    }
}

/// Browsers set up and connected, as text.
fn list(labels: impl Iterator<Item = String>) -> String {
    let mut out: Vec<String> = Vec::new();
    for l in labels {
        if !out.contains(&l) {
            out.push(l);
        }
    }
    out.join(", ")
}

/// *Settings → Desktop app*.
#[component]
pub fn BrowserRow() -> Element {
    let on = PREFS.read().browser_host;
    let agents_on = PREFS.read().agent_access;
    let mut registered_browsers = use_signal(status);
    let connected = crate::agent_access::BROWSERS_UI.read().clone();
    let mut ids = use_signal(|| PREFS.peek().extension_ids.join(", "));
    let mut failed = use_signal(|| false);
    let set_up: Vec<String> =
        registered_browsers.read().iter().filter(|(_, r)| *r).map(|(b, _)| b.label().to_string()).collect();
    let connected_text = list(
        connected
            .iter()
            .map(|b| format!("{} {}", twosecret_core::agent::browser_label(&b.browser), b.version).trim().to_string()),
    );
    let mut apply = move |turn_on: bool| {
        let ok = if turn_on { register(&PREFS.peek().extension_ids) } else { unregister() };
        failed.set(turn_on && !ok);
        if ok || !turn_on {
            PREFS.write().browser_host = turn_on;
            save_prefs();
        }
        registered_browsers.set(status());
    };
    rsx! {
        div { class: "settings-row",
            div { class: "k",
                div { class: "t", {t("agent.browser_row")} }
                div { class: "d", {t("agent.browser_row_desc")} }
                if !agents_on {
                    div { class: "d warn-text", {t("agent.browser_needs_agents")} }
                }
                if on {
                    if set_up.is_empty() {
                        div { class: "d warn-text", {t("agent.browser_none_found")} }
                    } else {
                        div { class: "d", {t("agent.browser_registered").replace("{browsers}", &list(set_up.iter().cloned()))} }
                    }
                    if connected_text.is_empty() {
                        div { class: "d", {t("agent.browser_none")} }
                    } else {
                        div { class: "d", {t("agent.browser_connected").replace("{browsers}", &connected_text)} }
                    }
                    div { class: "d small", style: "margin-top:8px", {t("agent.browser_dev_ids")} }
                    input { class: "input", r#type: "text", value: "{ids}", spellcheck: "false",
                        placeholder: "abcdefghijklmnopabcdefghijklmnop",
                        oninput: move |e| ids.set(e.value()),
                        onblur: move |_| {
                            let parsed: Vec<String> = ids
                                .read()
                                .split([',', ' ', ';', '\n'])
                                .map(|s| s.trim().to_lowercase())
                                .filter(|s| nm::valid_extension_id(s))
                                .collect();
                            if parsed != PREFS.peek().extension_ids {
                                PREFS.write().extension_ids = parsed.clone();
                                save_prefs();
                                register(&parsed);
                            }
                            ids.set(parsed.join(", "));
                        }
                    }
                }
                if failed() {
                    div { class: "d danger-text", {t("agent.browser_setup_failed")} }
                }
            }
            button { class: either(on, "btn small", "btn small primary"),
                onclick: move |_| apply(!on),
                {either(on, t("agent.browser_remove"), t("agent.browser_setup"))}
            }
        }
    }
}

#[cfg(windows)]
mod os {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::System::Registry::{
        RegDeleteKeyW, RegGetValueW, RegOpenKeyExW, RegSetKeyValueW, HKEY, HKEY_CURRENT_USER, KEY_READ, REG_SZ,
        RRF_RT_REG_SZ,
    };

    /// The default value of `HKCU\key`, when the key exists and has one.
    pub fn default_value(key: &str) -> Option<String> {
        let key = HSTRING::from(key);
        let mut size = 0u32;
        unsafe { RegGetValueW(HKEY_CURRENT_USER, &key, PCWSTR::null(), RRF_RT_REG_SZ, None, None, Some(&mut size)) }
            .ok()
            .ok()?;
        let mut buffer = vec![0u16; size as usize / 2 + 1];
        unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                &key,
                PCWSTR::null(),
                RRF_RT_REG_SZ,
                None,
                Some(buffer.as_mut_ptr().cast()),
                Some(&mut size),
            )
        }
        .ok()
        .ok()?;
        let text = String::from_utf16_lossy(&buffer[..size as usize / 2]);
        Some(text.trim_end_matches('\0').to_string())
    }

    pub fn key_exists(key: &str) -> bool {
        let mut handle = HKEY::default();
        let opened = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, &HSTRING::from(key), None, KEY_READ, &mut handle) };
        if opened.is_ok() {
            let _ = unsafe { windows::Win32::System::Registry::RegCloseKey(handle) };
            true
        } else {
            false
        }
    }

    /// Set the default value of `HKCU\key` (creating the key).
    pub fn set_default_value(key: &str, value: &str) -> bool {
        let data: Vec<u16> = value.encode_utf16().chain([0]).collect();
        unsafe {
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                &HSTRING::from(key),
                PCWSTR::null(),
                REG_SZ.0,
                Some(data.as_ptr().cast()),
                (data.len() * 2) as u32,
            )
        }
        .is_ok()
    }

    pub fn delete_key(key: &str) -> bool {
        unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, &HSTRING::from(key)) }.is_ok()
    }
}

#[cfg(not(windows))]
mod os {
    pub fn default_value(_key: &str) -> Option<String> {
        None
    }
    pub fn key_exists(_key: &str) -> bool {
        false
    }
    pub fn set_default_value(_key: &str, _value: &str) -> bool {
        false
    }
    pub fn delete_key(_key: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_program_means_same_name_and_size() {
        let dir = std::env::temp_dir().join(format!("2secret-same-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("a")).unwrap();
        std::fs::create_dir_all(dir.join("b")).unwrap();
        std::fs::write(dir.join("a/2-secret"), b"binary").unwrap();
        std::fs::write(dir.join("b/2-secret"), b"binary").unwrap();
        std::fs::write(dir.join("b/other"), b"binary").unwrap();
        std::fs::write(dir.join("b/2-secret.exe"), b"binary!").unwrap();
        assert!(same_file(&dir.join("a/2-secret"), &dir.join("b/2-secret")), "moved copy");
        assert!(!same_file(&dir.join("a/2-secret"), &dir.join("b/other")), "another name");
        assert!(!same_file(&dir.join("a/2-secret"), &dir.join("b/2-secret.exe")), "another size");
        assert!(!same_file(&dir.join("a/missing"), &dir.join("b/2-secret")));
        assert!(!same_program(None));
        let me = std::env::current_exe().unwrap();
        assert!(same_program(Some(&me.to_string_lossy())), "this very program");
        assert!(!same_program(Some(&dir.join("a/2-secret").to_string_lossy())));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifests_are_written_only_for_present_browsers() {
        let text = "{\"name\":\"x\"}";
        let dir = std::env::temp_dir().join(format!("2secret-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("Google/Chrome/NativeMessagingHosts").join(format!("{}.json", nm::HOST_NAME));
        assert!(write_if_changed(&path, text));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert!(write_if_changed(&path, text), "unchanged content is left alone");
        assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), modified);
        let present = Location { browser: Browser::Chrome, place: Place::Dir(path.parent().unwrap().to_path_buf()) };
        assert!(browser_present(&present) && registered(&present));
        let absent =
            Location { browser: Browser::Edge, place: Place::Dir(dir.join("Microsoft Edge/NativeMessagingHosts")) };
        assert!(!browser_present(&absent) && !registered(&absent));
        assert_eq!(
            list(["Chrome".to_string(), "Chrome".to_string(), "Firefox".to_string()].into_iter()),
            "Chrome, Firefox"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
