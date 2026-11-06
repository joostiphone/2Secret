//! Where vaults are kept: choosing a location (the account's server, this
//! device, a storage folder), moving vaults, and how vaults in storage
//! folders are doing.

use dioxus::prelude::*;
use twosecret_core::folder::{Availability, Platform};
use twosecret_core::profile::{FolderService, MoveTarget, VaultLocation};
use twosecret_core::session::VaultInfo;

use crate::components::widgets::ModalFrame;
use crate::i18n::t;
use crate::icons::{either, vault_icon, Icon};
use crate::state::*;

/// A location as chosen in a form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    Account,
    Device,
    Folder(FolderService),
}

impl Place {
    pub fn of(location: &VaultLocation) -> Place {
        match location {
            VaultLocation::Account => Place::Account,
            VaultLocation::Device => Place::Device,
            VaultLocation::Folder { service, .. } => Place::Folder(*service),
        }
    }

    fn kind(&self) -> u8 {
        match self {
            Place::Account => 0,
            Place::Device => 1,
            Place::Folder(_) => 2,
        }
    }
}

pub fn service_name(service: FolderService) -> &'static str {
    match service {
        FolderService::Other => t("location.other_folder"),
        other => other.name(),
    }
}

/// A platform's name in a sentence.
fn platform_name(p: Platform) -> &'static str {
    t(match p {
        Platform::MacOs => "platform.macos",
        Platform::Windows => "platform.windows",
        Platform::Linux => "platform.linux",
        Platform::Bsd => "platform.bsd",
        Platform::Ios => "platform.ios",
        Platform::Android => "platform.android",
        Platform::Web => "platform.web",
    })
}

/// A platform's name in the table.
fn platform_short(p: Platform) -> &'static str {
    match p {
        Platform::MacOs => "macOS",
        Platform::Windows => "Windows",
        Platform::Linux => "Linux",
        Platform::Bsd => "BSD",
        Platform::Ios => "iPhone/iPad",
        Platform::Android => "Android",
        Platform::Web => t("platform.web_short"),
    }
}

/// "A, B and C".
fn join_list(parts: &[&str]) -> String {
    match parts {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} {} {last}", rest.join(", "), t("common.and")),
    }
}

/// Where a vault is, in a few words ("iCloud Drive", "This device only").
pub fn location_label(v: &VaultInfo, linked: bool) -> String {
    if let Some(moved) = &v.moved {
        return match &moved.to {
            MoveTarget::Folder { service, .. } => service_name(*service).to_string(),
            _ => t("location.elsewhere").to_string(),
        };
    }
    match &v.location {
        VaultLocation::Account if linked => t("location.on_server").to_string(),
        VaultLocation::Account => t("location.on_device").to_string(),
        VaultLocation::Device => t("location.device").to_string(),
        VaultLocation::Folder { service, .. } => service_name(*service).to_string(),
    }
}

/// The icon of a vault's location, for vaults not on the account's server.
pub fn location_icon(v: &VaultInfo) -> Option<&'static str> {
    if v.is_placeholder() {
        return Some("cloud-off");
    }
    match v.location {
        VaultLocation::Account => None,
        VaultLocation::Device => Some("smartphone"),
        VaultLocation::Folder { .. } => Some("folder"),
    }
}

/// The folder a storage service keeps in sync on this device, if found.
fn suggested(service: FolderService) -> Option<String> {
    #[cfg(all(feature = "desktop", not(any(target_os = "ios", target_os = "android"))))]
    {
        twosecret_client::folder::suggested_folder(service).map(|p| p.to_string_lossy().into_owned())
    }
    #[cfg(not(all(feature = "desktop", not(any(target_os = "ios", target_os = "android")))))]
    {
        let _ = service;
        None
    }
}

/// The service offered first: the first one found on this device.
fn first_service() -> FolderService {
    #[cfg(all(feature = "desktop", not(any(target_os = "ios", target_os = "android"))))]
    {
        twosecret_client::folder::service_roots().first().map(|(s, _)| *s).unwrap_or_default()
    }
    #[cfg(not(all(feature = "desktop", not(any(target_os = "ios", target_os = "android")))))]
    {
        FolderService::Other
    }
}

/// Let the person choose a folder.
async fn pick_folder(start: String) -> Option<String> {
    #[cfg(all(feature = "desktop", not(any(target_os = "ios", target_os = "android"))))]
    {
        let mut dialog = rfd::AsyncFileDialog::new().set_title(t("location.choose_title"));
        if std::path::Path::new(&start).is_dir() {
            dialog = dialog.set_directory(&start);
        }
        dialog.pick_folder().await.map(|h| h.path().to_string_lossy().into_owned())
    }
    #[cfg(not(all(feature = "desktop", not(any(target_os = "ios", target_os = "android")))))]
    {
        let _ = start;
        None
    }
}

/// Where a vault in this service's folder can be used, and what that means.
#[component]
pub fn AvailabilityNote(service: FolderService) -> Element {
    let rows = service.availability();
    let missing: Vec<&str> = service.missing_on().into_iter().map(platform_name).collect();
    let later: Vec<&str> =
        rows.iter().filter(|(_, a)| *a == Availability::Later).map(|(p, _)| platform_name(*p)).collect();
    let missing_text = (!missing.is_empty()).then(|| {
        t("location.missing").replace("{service}", service_name(service)).replace("{platforms}", &join_list(&missing))
    });
    let later_text = (!later.is_empty()).then(|| t("location.later").replace("{platforms}", &join_list(&later)));
    rsx! {
        div { class: "availability", role: "list", aria_label: t("location.where"),
            for (p, a) in rows {
                span { key: "{p:?}", role: "listitem",
                    class: match a { Availability::Yes => "avail yes", Availability::Later => "avail later", Availability::No => "avail no" },
                    title: match a { Availability::Yes => t("location.works"), Availability::Later => t("location.works_later"), Availability::No => t("location.no_app") },
                    match a { Availability::Yes => "✓ ", Availability::Later => "… ", Availability::No => "✗ " }
                    {platform_short(p)}
                }
            }
        }
        if let Some(text) = missing_text {
            div { class: "note warn", Icon { name: "alert", size: 14 } span { "{text}" } }
        }
        if let Some(text) = later_text {
            div { class: "note", Icon { name: "clock", size: 14 } span { "{text}" } }
        }
    }
}

/// The choice of where a vault is kept, with the folder for a storage
/// service.
#[component]
pub fn LocationPicker(place: Signal<Place>, folder: Signal<String>, #[props(default)] keep_device: bool) -> Element {
    let session = SESSION.read();
    let linked = session.as_ref().is_some_and(|s| s.server().is_some());
    let host = session
        .as_ref()
        .and_then(|s| {
            s.server().map(|l| l.url.trim_start_matches("https://").trim_start_matches("http://").to_string())
        })
        .unwrap_or_default();
    drop(session);
    let mut options: Vec<(Place, &str, String, &str)> = Vec::new();
    if linked {
        options.push((
            Place::Account,
            "cloud",
            t("location.server").replace("{host}", &host),
            t("location.server_desc"),
        ));
        options.push((Place::Device, "smartphone", t("location.device").to_string(), t("location.device_desc")));
    } else {
        options.push((Place::Account, "smartphone", t("location.on_device").to_string(), t("location.local_desc")));
        // Kept off the account already: going "with the account" is a change.
        if keep_device {
            options.push((Place::Device, "smartphone", t("location.device").to_string(), t("location.device_desc")));
        }
    }
    if FOLDER_VAULTS {
        options.push((
            Place::Folder(first_service()),
            "folder",
            t("location.folder").to_string(),
            t("location.folder_desc"),
        ));
    }
    let current = place();
    rsx! {
        div { class: "form-group",
            label { class: "label", {t("location.label")} }
            for (option , icon , title , desc) in options {
                button { key: "{option.kind()}", r#type: "button",
                    class: either(current.kind() == option.kind(), "choice compact on", "choice compact"),
                    onclick: move |_| {
                        if current.kind() == option.kind() {
                            return;
                        }
                        if let Place::Folder(s) = option {
                            folder.set(suggested(s).unwrap_or_default());
                        }
                        place.set(option);
                    },
                    Icon { name: icon, size: 20 }
                    div {
                        div { class: "t", "{title}" }
                        div { class: "d", "{desc}" }
                    }
                }
            }
            if let Place::Folder(service) = current {
                div { class: "chips services", role: "radiogroup", aria_label: t("location.service"),
                    for s in FolderService::ALL {
                        button { key: "{s.id()}", r#type: "button", role: "radio", aria_checked: s == service,
                            class: either(s == service, "chip on", "chip"),
                            onclick: move |_| {
                                place.set(Place::Folder(s));
                                folder.set(suggested(s).unwrap_or_default());
                            },
                            {service_name(s)}
                        }
                    }
                }
                div { class: "folder-row",
                    input { class: "input", value: "{folder}", placeholder: t("location.folder_placeholder"),
                        autocapitalize: "off", spellcheck: "false",
                        oninput: move |e| folder.set(e.value()) }
                    button { r#type: "button", class: "btn small",
                        onclick: move |_| {
                            spawn(async move {
                                if let Some(path) = pick_folder(folder()).await {
                                    folder.set(path);
                                }
                            });
                        },
                        Icon { name: "folder", size: 14 }
                        {t("location.choose")}
                    }
                }
                if service != FolderService::Other && suggested(service).is_none() {
                    div { class: "note", Icon { name: "alert", size: 14 }
                        span { {t("location.not_here").replace("{service}", service_name(service))} }
                    }
                }
                AvailabilityNote { service }
            }
        }
    }
}

/// Create a vault at the chosen place. Returns its id.
pub async fn create_at(
    name: String,
    description: String,
    icon: &'static str,
    place: Place,
    folder: String,
) -> Option<String> {
    let location = match place {
        Place::Account => VaultLocation::Account,
        Place::Device => VaultLocation::Device,
        Place::Folder(service) => {
            return create_in_folder(name, description, icon, service, folder).await;
        }
    };
    mutate(|s| {
        let id = s.create_vault_at(&name, &description, location)?;
        s.update_vault(&id, &name, &description, Some(icon))?;
        Ok(id)
    })
}

#[cfg(all(feature = "desktop", not(any(target_os = "ios", target_os = "android"))))]
async fn create_in_folder(
    name: String,
    description: String,
    icon: &'static str,
    service: FolderService,
    folder: String,
) -> Option<String> {
    if folder.trim().is_empty() {
        toast_err(t("location.no_folder"));
        return None;
    }
    let mut session = session_copy()?;
    busy(t("busy.working"));
    let path = std::path::PathBuf::from(folder.trim());
    let result = twosecret_client::folder::create_folder_vault(&mut session, &name, &description, &path, service).await;
    unbusy();
    match result {
        Ok(id) => {
            let _ = session.update_vault(&id, &name, &description, Some(icon));
            install_session(session);
            request_sync();
            Some(id)
        }
        Err(e) => {
            toast_err(&client_error(&e));
            None
        }
    }
}

#[cfg(not(all(feature = "desktop", not(any(target_os = "ios", target_os = "android")))))]
async fn create_in_folder(_: String, _: String, _: &'static str, _: FolderService, _: String) -> Option<String> {
    None
}

/// Take a vault from a folder: one made on another device, a placeholder's
/// vault, or a folder vault whose folder is somewhere else now.
pub fn choose_folder_for(vault: Option<VaultInfo>) {
    #[cfg(all(feature = "desktop", not(any(target_os = "ios", target_os = "android"))))]
    spawn(async move {
        let service = vault.as_ref().and_then(|v| match (&v.location, v.moved.as_ref().map(|m| &m.to)) {
            (VaultLocation::Folder { service, .. }, _) => Some(*service),
            (_, Some(MoveTarget::Folder { service, .. })) => Some(*service),
            _ => None,
        });
        let start = service.and_then(suggested).unwrap_or_default();
        let Some(path) = pick_folder(start).await else { return };
        let Some(mut session) = session_copy() else { return };
        busy(t("busy.working"));
        let result = twosecret_client::folder::attach_folder(&mut session, std::path::Path::new(&path), service).await;
        unbusy();
        match result {
            Ok(id) => {
                if let Some(v) = vault.as_ref().filter(|v| v.id != id) {
                    toast_err(&t("location.other_vault").replace("{name}", &v.name));
                }
                install_session(session);
                *NAV.write() = Nav::Vault(id);
                *SELECTED.write() = None;
                toast(t("location.added"));
                request_sync();
            }
            Err(e) => toast_err(&client_error(&e)),
        }
    });
    #[cfg(not(all(feature = "desktop", not(any(target_os = "ios", target_os = "android")))))]
    let _ = vault;
}

/// Above the items of a vault kept elsewhere: where it is, how it is doing.
#[component]
pub fn VaultPlaceBanner(vault: VaultInfo) -> Element {
    let folders = FOLDERS.read();
    let status = folders.get(&vault.id).cloned();
    drop(folders);
    if let Some(moved) = vault.moved.clone().filter(|_| vault.is_placeholder()) {
        let (service, folder) = match &moved.to {
            MoveTarget::Folder { service, folder } => (service_name(*service), folder.clone()),
            other => (t("location.elsewhere"), other.to_string()),
        };
        let text = if FOLDER_VAULTS { t("placeholder.desktop") } else { t("placeholder.not_here") };
        let v = vault.clone();
        return rsx! {
            div { class: "banner",
                Icon { name: "cloud-off", size: 18 }
                div { class: "grow",
                    div { class: "t", {t("placeholder.title").replace("{service}", service)} }
                    div { class: "d", "{folder} · {text}" }
                }
                if FOLDER_VAULTS {
                    button { class: "btn small primary", onclick: move |_| choose_folder_for(Some(v.clone())), {t("location.choose_folder")} }
                }
            }
        };
    }
    let VaultLocation::Folder { service, path } = vault.location.clone() else { return rsx! {} };
    let Some(status) = status else { return rsx! {} };
    if status.not_found || status.error.is_some() {
        let v = vault.clone();
        let detail = if status.not_found { path.clone() } else { status.error.clone().unwrap_or_default() };
        return rsx! {
            div { class: "banner warn",
                Icon { name: "alert", size: 18 }
                div { class: "grow",
                    div { class: "t", {either(status.not_found, t("folder.not_found"), t("folder.error"))} }
                    div { class: "d", "{detail}" }
                }
                if status.not_found {
                    button { class: "btn small", onclick: move |_| choose_folder_for(Some(v.clone())), {t("location.choose_folder")} }
                }
            }
        };
    }
    if status.waiting > 0 {
        return rsx! {
            div { class: "place-line muted small", Icon { name: "clock", size: 13 }
                {t("folder.waiting").replace("{service}", service_name(service)).replace("{n}", &status.waiting.to_string())}
            }
        };
    }
    let ago = status.synced_at.map(crate::components::shell::relative_time).unwrap_or_default();
    rsx! {
        div { class: "place-line muted small", title: "{path}", Icon { name: "folder", size: 13 }
            {t("folder.synced").replace("{service}", service_name(service)).replace("{ago}", &ago)}
        }
    }
}

/// Move a vault to another place.
#[component]
pub fn MoveVaultModal(id: String) -> Element {
    let Some(vault) = SESSION.peek().as_ref().and_then(|s| s.vault(&id)) else { return rsx! {} };
    let linked = SESSION.peek().as_ref().is_some_and(|s| s.server().is_some());
    let from = Place::of(&vault.location);
    let place = use_signal(|| from);
    let folder = use_signal(String::new);
    let emergency = EMERGENCY.peek().as_ref().is_some_and(|e| !e.contacts.is_empty());
    let shared = vault.is_shared();
    let same = place().kind() == from.kind() && !matches!(place(), Place::Folder(_));
    let id2 = id.clone();
    let start = move |_| {
        let to = place();
        let target = match to {
            Place::Account => MoveChoice::Account,
            Place::Device => MoveChoice::Device,
            Place::Folder(service) => {
                if folder().trim().is_empty() {
                    toast_err(t("location.no_folder"));
                    return;
                }
                MoveChoice::Folder(folder().trim().to_string(), service)
            }
        };
        let id = id2.clone();
        spawn(async move {
            if move_to(&id, target).await {
                *MODAL.write() = None;
                toast(t("move.done"));
            }
        });
    };
    rsx! {
        ModalFrame { title: t("move.title"),
            footer: rsx! {
                button { class: "btn", onclick: move |_| *MODAL.write() = None, {t("common.cancel")} }
                if !shared {
                    button { class: "btn primary", disabled: same, onclick: start, {t("move.go")} }
                }
            },
            div { class: "settings-row plain",
                Icon { name: vault_icon(&vault.icon, vault.is_shared()), size: 18 }
                div { class: "k",
                    div { class: "t", "{vault.name}" }
                    div { class: "d", "{vault.item_count} {t(\"vault.items\")} · {location_label(&vault, linked)}" }
                }
            }
            if shared {
                div { class: "note warn", Icon { name: "users", size: 14 } span { {t("move.shared")} } }
            } else {
                LocationPicker { place, folder, keep_device: from == Place::Device }
                if place() == Place::Device && linked && from != Place::Device {
                    div { class: "note warn", Icon { name: "alert", size: 14 } span { {t("move.device_warning")} } }
                }
                if emergency && from == Place::Account && place() != Place::Account {
                    div { class: "note warn", Icon { name: "shield", size: 14 } span { {t("move.emergency")} } }
                }
                p { class: "muted small", {t("move.how")} }
            }
        }
    }
}

enum MoveChoice {
    Account,
    Device,
    #[cfg_attr(not(all(feature = "desktop", not(any(target_os = "ios", target_os = "android")))), allow(dead_code))]
    Folder(String, FolderService),
}

#[cfg(all(feature = "desktop", not(any(target_os = "ios", target_os = "android"))))]
async fn move_to(id: &str, target: MoveChoice) -> bool {
    use twosecret_client::folder::MoveTo;
    let to = match target {
        MoveChoice::Account => MoveTo::Account,
        MoveChoice::Device => MoveTo::Device,
        MoveChoice::Folder(path, service) => MoveTo::Folder { parent: path.into(), service },
    };
    let Some(mut session) = session_copy() else { return false };
    busy(t("busy.moving"));
    let result = twosecret_client::folder::move_vault(&mut session, id, to).await;
    unbusy();
    // Partly done is still worth keeping (the vault is safe where it is now).
    install_session(session);
    match result {
        Ok(()) => {
            request_sync();
            true
        }
        Err(e) => {
            report_error(&e, |m| toast_err(&m));
            false
        }
    }
}

/// Without storage folders (web, phones): between the server and this
/// device, with the same steps.
#[cfg(not(all(feature = "desktop", not(any(target_os = "ios", target_os = "android")))))]
async fn move_to(id: &str, target: MoveChoice) -> bool {
    let to = match target {
        MoveChoice::Account => VaultLocation::Account,
        MoveChoice::Device => VaultLocation::Device,
        MoveChoice::Folder(..) => return false,
    };
    let Some(mut session) = session_copy() else { return false };
    busy(t("busy.moving"));
    let linked = session.server().is_some();
    let result: twosecret_client::Result<()> = async {
        if linked {
            twosecret_client::sync(&mut session).await?;
        }
        let was_on_server = linked
            && session
                .profile()
                .vault(id)
                .is_some_and(|v| v.location.is_account() && v.sync_state == twosecret_core::profile::SyncState::Synced);
        session.relocate_vault(id, to.clone())?;
        if linked {
            match to {
                VaultLocation::Device if was_on_server => {
                    let _ = twosecret_client::client_for(&session)?.delete_vault(id).await;
                }
                _ => {
                    twosecret_client::sync(&mut session).await?;
                }
            }
        }
        Ok(())
    }
    .await;
    unbusy();
    install_session(session);
    match result {
        Ok(()) => true,
        Err(e) => {
            report_error(&e, |m| toast_err(&m));
            false
        }
    }
}

/// Delete a vault kept in a storage folder: its files go too.
pub fn delete_folder_vault(id: String) {
    #[cfg(all(feature = "desktop", not(any(target_os = "ios", target_os = "android"))))]
    spawn(async move {
        let Some(mut session) = session_copy() else { return };
        busy(t("busy.working"));
        let result = twosecret_client::folder::delete_folder_vault(&mut session, &id).await;
        unbusy();
        install_session(session);
        match result {
            Ok(()) => {
                *NAV.write() = Nav::All;
                *SELECTED.write() = None;
                *MODAL.write() = None;
            }
            Err(e) => toast_err(&client_error(&e)),
        }
    });
    #[cfg(not(all(feature = "desktop", not(any(target_os = "ios", target_os = "android")))))]
    {
        if mutate(|s| s.delete_vault(&id)).is_some() {
            *NAV.write() = Nav::All;
            *MODAL.write() = None;
        }
    }
}
