//! Settings: account, sync, security, appearance, import/export and more.

use dioxus::prelude::*;
use twosecret_core::api::DeviceInfo;
use twosecret_core::biometric::BiometricUnlock;
use twosecret_core::import::{self, ImportFormat};

use crate::biometric;
use crate::components::shell::{nav_title, relative_time};
use crate::components::widgets::*;
use crate::i18n::{t, Lang, LANG};
use crate::icons::{either, vault_icon, AccountAvatar, Icon};
use crate::platform;
use crate::state::*;

#[component]
pub fn SettingsPage() -> Element {
    rsx! {
        div { class: "toolbar",
            button { class: "icon-btn mobile-only", onclick: move |_| *PANE.write() = Pane::Nav, Icon { name: "menu" } }
            span { class: "grow", style: "font-weight:600;font-size:16px", {t("nav.settings")} }
        }
        div { class: "detail-scroll",
            div { class: "detail-inner",
                AccountSection {}
                SyncSection {}
                VaultsSection {}
                SecuritySection {}
                AppearanceSection {}
                ImportSection {}
                ExportSection {}
                UpdatesSection {}
                AboutSection {}
                DangerSection {}
            }
        }
    }
}

/// `1.2 MB` (decimal units, like the server's limit), `1,2 MB` in Dutch.
fn format_size(bytes: u64) -> String {
    let (value, unit) = match bytes {
        b if b >= 1_000_000_000 => (b as f64 / 1e9, "GB"),
        b if b >= 1_000_000 => (b as f64 / 1e6, "MB"),
        b => (b as f64 / 1e3, "kB"),
    };
    let text = format!("{value:.1} {unit}");
    if LANG() == Lang::Nl {
        text.replace('.', ",")
    } else {
        text
    }
}

#[component]
fn SectionTitle(text: String) -> Element {
    rsx! { div { class: "section-title", "{text}" } }
}

#[component]
fn AccountSection() -> Element {
    let mut show_sk = use_signal(|| false);
    let mut changing = use_signal(|| false);
    let session = SESSION.read();
    let Some(s) = session.as_ref() else { return rsx! {} };
    let account = s.account().clone();
    let photo = s.avatar();
    let server = s.server().map(|l| l.url.clone());
    let fingerprint = s.public_keys().fingerprint();
    drop(session);
    let sk = secret_key();
    let sk_text = sk.as_ref().map(|k| if show_sk() { k.formatted() } else { k.masked() }).unwrap_or_default();

    let download_kit = move |_| {
        let (Some(sk), Some((name, email, server))) = (
            secret_key(),
            SESSION
                .peek()
                .as_ref()
                .map(|s| (s.account().name.clone(), s.account().email.clone(), s.server().map(|l| l.url.clone()))),
        ) else {
            return;
        };
        let html = twosecret_core::emergency_kit::html(&name, &email, server.as_deref(), &sk);
        spawn(async move {
            match platform::save_file("2Secret-Emergency-Kit.html", "text/html", html.as_bytes()).await {
                Ok(w) => toast(&format!("{} {w}", t("toast.saved_to"))),
                Err(e) => toast_err(&e),
            }
        });
    };

    rsx! {
        div { class: "section",
            SectionTitle { text: t("settings.account") }
            div { class: "settings-row",
                AccountAvatar { name: account.name.clone(), photo: photo.clone(), size: 44 }
                div { class: "k",
                    div { class: "t", "{account.name}" }
                    div { class: "d", "{account.email}" }
                }
                label { class: "btn small", title: t("settings.photo_desc"),
                    {either(photo.is_some(), t("settings.photo_change"), t("settings.photo_add"))}
                    input { r#type: "file", accept: "image/*", class: "file-input",
                        onchange: move |e| {
                            let files = e.files();
                            spawn(async move {
                                let Some(f) = files.into_iter().next() else { return };
                                let bytes = match f.read_bytes().await {
                                    Ok(b) => b.to_vec(),
                                    Err(err) => return toast_err(&err.to_string()),
                                };
                                match platform::run_heavy(move || crate::avatar::prepare(&bytes)).await {
                                    Ok(url) => {
                                        if mutate(|s| s.set_avatar(Some(&url))).is_some() {
                                            toast(t("settings.photo_saved"));
                                        }
                                    }
                                    Err(_) => toast_err(t("settings.photo_invalid")),
                                }
                            });
                        }
                    }
                }
                if photo.is_some() {
                    button { class: "btn small", onclick: move |_| { mutate(|s| s.set_avatar(None)); }, {t("common.remove")} }
                }
            }
            div { class: "settings-row",
                div { class: "k",
                    div { class: "t", {t("common.secret_key")} }
                    div { class: "d mono", "{sk_text}" }
                }
                button { class: "icon-btn", onclick: move |_| show_sk.toggle(), Icon { name: either(show_sk(), "eye-off", "eye"), size: 16 } }
                button { class: "icon-btn", onclick: move |_| { if let Some(k) = secret_key() { copy(k.formatted(), t("common.secret_key")); } },
                    Icon { name: "copy", size: 16 }
                }
            }
            div { class: "settings-row",
                div { class: "k",
                    div { class: "t", {t("settings.emergency_kit")} }
                    div { class: "d", {t("settings.emergency_kit_desc")} }
                }
                button { class: "btn small", onclick: download_kit, Icon { name: "download", size: 15 } {t("common.download")} }
            }
            div { class: "settings-row",
                div { class: "k",
                    div { class: "t", {t("settings.change_password")} }
                    div { class: "d", {t("settings.change_password_desc")} }
                }
                button { class: "btn small", onclick: move |_| changing.toggle(), {t("common.change")} }
            }
            if changing() {
                ChangePasswordForm { done: move |_| changing.set(false) }
            }
            div { class: "settings-row",
                div { class: "k",
                    div { class: "t", {t("settings.fingerprint")} }
                    div { class: "d mono", "{fingerprint}" }
                }
            }
            if let Some(url) = server {
                div { class: "settings-row",
                    div { class: "k",
                        div { class: "t", {t("common.server")} }
                        div { class: "d", "{url}" }
                    }
                }
            }
        }
    }
}

#[component]
fn ChangePasswordForm(done: EventHandler<()>) -> Element {
    let mut current = use_signal(String::new);
    let mut new = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let submit = move |_| {
        let (cur, nw, cf) = (current(), new(), confirm());
        let context = SESSION
            .peek()
            .as_ref()
            .map(|s| (s.profile().account.name.clone(), s.profile().account.email.clone()))
            .unwrap_or_default();
        if let Err(problem) = twosecret_core::session::check_master_password(&nw, &[&context.0, &context.1]) {
            error.set(Some(
                match problem {
                    twosecret_core::session::PasswordProblem::TooShort => t("create.err_short"),
                    twosecret_core::session::PasswordProblem::TooWeak => t("create.err_weak"),
                }
                .into(),
            ));
            return;
        }
        if nw != cf {
            error.set(Some(t("create.err_mismatch").into()));
            return;
        }
        let (Some(session), Some(sk)) = (session_copy(), secret_key()) else { return };
        error.set(None);
        spawn(async move {
            busy(t("busy.changing_password"));
            let (mut session, change) = platform::run_heavy(move || {
                let c = session.prepare_password_change(&cur, &nw, &sk);
                (session, c)
            })
            .await;
            let change = match change {
                Ok(c) => c,
                Err(e) => {
                    unbusy();
                    error.set(Some(core_error(&e)));
                    return;
                }
            };
            let result = twosecret_client::submit_password_change(&mut session, &change).await;
            unbusy();
            match result {
                Ok(()) => {
                    install_session(session);
                    password_entered();
                    toast(t("toast.password_changed"));
                    done.call(());
                }
                Err(e) => error.set(Some(client_error(&e))),
            }
        });
    };
    rsx! {
        div { class: "section-body", style: "padding-top:12px;border-bottom:1px solid var(--border)",
            if let Some(err) = error() { div { class: "error-box", "{err}" } }
            div { class: "form-group",
                label { class: "label", {t("settings.current_password")} }
                PasswordInput { value: current(), oninput: move |v| current.set(v) }
            }
            div { class: "form-group",
                label { class: "label", {t("settings.new_password")} }
                PasswordInput { value: new(), oninput: move |v| new.set(v) }
                StrengthMeter { password: new() }
            }
            div { class: "form-group",
                label { class: "label", {t("create.confirm")} }
                PasswordInput { value: confirm(), oninput: move |v| confirm.set(v) }
            }
            div { class: "info-box small", {t("settings.change_password_info")} }
            div { class: "row",
                button { class: "btn primary", onclick: submit, {t("settings.change_password")} }
                button { class: "btn ghost", onclick: move |_| done.call(()), {t("common.cancel")} }
            }
        }
    }
}

#[component]
fn SyncSection() -> Element {
    let mut devices = use_signal(|| None::<Vec<DeviceInfo>>);
    let mut connecting = use_signal(|| false);
    // (used, limit) on the server, when it says.
    let mut storage = use_signal(|| None::<(u64, Option<u64>)>);
    use_hook(move || {
        let client = SESSION.peek().as_ref().and_then(|s| twosecret_client::client_for(s).ok());
        if let Some(client) = client {
            spawn(async move {
                if let Ok(account) = client.account().await {
                    storage.set(account.storage_used.map(|used| (used, account.storage_quota)));
                }
            });
        }
    });
    let session = SESSION.read();
    let Some(s) = session.as_ref() else { return rsx! {} };
    let link = s.server().cloned();
    let signed_in = s.server_token().is_some();
    let pending = s.profile().has_pending_changes();
    drop(session);
    let status = SYNC.read().clone();

    let load_devices = move |_| {
        let client = SESSION.peek().as_ref().and_then(|s| twosecret_client::client_for(s).ok());
        let Some(client) = client else { return };
        spawn(async move {
            match client.devices().await {
                Ok(list) => devices.set(Some(list)),
                Err(e) => toast_err(&client_error(&e)),
            }
        });
    };

    rsx! {
        div { class: "section",
            SectionTitle { text: t("settings.sync") }
            match link {
                None => rsx! {
                    div { class: "settings-row",
                        div { class: "k",
                            div { class: "t", {t("settings.local_only")} }
                            div { class: "d", {t("settings.local_only_desc")} }
                        }
                        button { class: "btn small primary", onclick: move |_| connecting.toggle(), Icon { name: "cloud", size: 15 } {t("settings.connect")} }
                    }
                    if connecting() {
                        ConnectForm { done: move |_| connecting.set(false) }
                    }
                },
                Some(link) => rsx! {
                    div { class: "settings-row",
                        div { class: "k",
                            div { class: "t", "{link.url}" }
                            div { class: "d",
                                if !signed_in {
                                    span { class: "danger-text", {t("sync.signed_out")} }
                                } else if let Some(err) = status.error.clone() {
                                    span { class: "danger-text", "{err}" }
                                } else if let Some(ts) = link.last_sync_at {
                                    "{t(\"sync.synced\")} {relative_time(ts)}"
                                } else {
                                    {t("sync.never")}
                                }
                                if pending { " · {t(\"settings.pending\")}" }
                            }
                        }
                        if signed_in && !status.needs_reauth {
                            button { class: "btn small", disabled: status.running, onclick: move |_| { dioxus::core::spawn_forever(run_sync(true)); },
                                Icon { name: "refresh", size: 15 }
                                {t("sync.now")}
                            }
                        } else {
                            button { class: "btn small primary", onclick: move |_| *MODAL.write() = Some(Modal::Reauth), {t("settings.sign_in_again")} }
                        }
                    }
                    if let Some((used, quota)) = storage() {
                        div { class: "settings-row",
                            div { class: "k",
                                div { class: "t", {t("settings.storage")} }
                                div { class: "d",
                                    match quota {
                                        Some(q) => t("settings.storage_of").replace("{used}", &format_size(used)).replace("{quota}", &format_size(q)),
                                        None => format_size(used),
                                    }
                                }
                            }
                        }
                    }
                    if signed_in {
                        div { class: "settings-row",
                            div { class: "k",
                                div { class: "t", {t("settings.devices")} }
                                div { class: "d", {t("settings.devices_desc")} }
                            }
                            button { class: "btn small", onclick: load_devices, {t("common.show")} }
                        }
                        if let Some(list) = devices() {
                            for d in list {
                                div { class: "settings-row", key: "{d.id}",
                                    Icon { name: "smartphone", size: 16 }
                                    div { class: "k",
                                        div { class: "t", "{d.name}" if d.current { " ({t(\"settings.this_device\")})" } }
                                        div { class: "d", "{t(\"settings.last_used\")} {platform::local_time(d.last_used_at)}" }
                                    }
                                    if !d.current {
                                        button { class: "btn small danger",
                                            onclick: move |_| {
                                                let client = SESSION.peek().as_ref().and_then(|s| twosecret_client::client_for(s).ok());
                                                let Some(client) = client else { return };
                                                let id = d.id.clone();
                                                spawn(async move {
                                                    match client.revoke_device(&id).await {
                                                        Ok(()) => {
                                                            devices.with_mut(|l| if let Some(l) = l { l.retain(|x| x.id != id) });
                                                            toast(t("toast.device_removed"));
                                                        }
                                                        Err(e) => toast_err(&client_error(&e)),
                                                    }
                                                });
                                            },
                                            {t("settings.sign_out_device")}
                                        }
                                    }
                                }
                            }
                        }
                        div { class: "settings-row",
                            div { class: "k",
                                div { class: "t", {t("settings.sign_out")} }
                                div { class: "d", {t("settings.sign_out_desc")} }
                            }
                            button { class: "btn small",
                                onclick: move |_| {
                                    let Some(mut s) = session_copy() else { return };
                                    spawn(async move {
                                        busy(t("busy.working"));
                                        let _ = twosecret_client::sign_out(&mut s).await;
                                        install_session(s);
                                        unbusy();
                                        SYNC.write().needs_reauth = true;
                                    });
                                },
                                Icon { name: "logout", size: 15 }
                                {t("settings.sign_out")}
                            }
                        }
                    }
                },
            }
        }
    }
}

#[component]
fn ConnectForm(done: EventHandler<()>) -> Element {
    let (initial, initial_url) = ServerChoice::initial(false);
    let choice = use_signal(|| initial);
    let server = use_signal(move || initial_url.clone());
    let mut invite = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let submit = move |_| {
        let url = choice().url(&server()).unwrap_or_default();
        let inv = if choice() == ServerChoice::Custom { invite() } else { String::new() };
        let pw = password();
        if url.trim().is_empty() || pw.is_empty() {
            error.set(Some(t("signin.err_fields").into()));
            return;
        }
        let (Some(session), Some(sk)) = (session_copy(), secret_key()) else { return };
        error.set(None);
        spawn(async move {
            busy(t("busy.registering"));
            let (mut session, keys) = platform::run_heavy(move || {
                let k = session.verify_password(&pw, &sk);
                (session, k)
            })
            .await;
            let keys = match keys {
                Ok(k) => k,
                Err(e) => {
                    unbusy();
                    error.set(Some(core_error(&e)));
                    return;
                }
            };
            let inv = (!inv.trim().is_empty()).then(|| inv.trim().to_string());
            let result = twosecret_client::connect_with_keys(
                &mut session,
                &url,
                &keys,
                inv.as_deref(),
                &platform::device_name(),
            )
            .await;
            unbusy();
            match result {
                Ok(_) => {
                    install_session(session);
                    toast(t("toast.connected"));
                    done.call(());
                }
                Err(e) => error.set(Some(client_error(&e))),
            }
        });
    };
    rsx! {
        div { class: "section-body", style: "padding-top:12px",
            if let Some(err) = error() { div { class: "error-box", "{err}" } }
            label { class: "label", {t("common.server")} }
            ServerPicker { choice, custom: server }
            if choice() == ServerChoice::Custom {
                div { class: "form-group",
                    label { class: "label", {t("create.invite")} }
                    input { class: "input", initial_value: "{invite}", placeholder: t("common.optional"), oninput: move |e| invite.set(e.value()) }
                }
            }
            div { class: "form-group",
                label { class: "label", {t("common.master_password")} }
                PasswordInput { value: password(), oninput: move |v| password.set(v) }
            }
            div { class: "row",
                button { class: "btn primary", onclick: submit, {t("settings.connect")} }
                button { class: "btn ghost", onclick: move |_| done.call(()), {t("common.cancel")} }
            }
        }
    }
}

#[component]
fn VaultsSection() -> Element {
    let vaults = SESSION.read().as_ref().map(|s| s.vaults()).unwrap_or_default();
    let linked = SESSION.read().as_ref().is_some_and(|s| s.server().is_some());
    rsx! {
        div { class: "section",
            SectionTitle { text: t("nav.vaults") }
            for v in vaults {
                div { class: "settings-row", key: "{v.id}",
                    Icon { name: vault_icon(&v.icon, v.is_shared()), size: 18 }
                    div { class: "k",
                        div { class: "t", "{v.name}" }
                        div { class: "d",
                            "{v.item_count} {t(\"vault.items\")} · {crate::i18n::role_name(v.role)}"
                            if v.is_shared() { " · {v.member_count} {t(\"vault.members\")}" }
                        }
                    }
                    if linked && v.role.can_manage() {
                        button { class: "icon-btn", title: t("vault.share"), onclick: { let id = v.id.clone(); move |_| *MODAL.write() = Some(Modal::ShareVault(id.clone())) },
                            Icon { name: "share", size: 16 }
                        }
                    }
                    if v.role.can_manage() {
                        button { class: "icon-btn", title: t("vault.edit"), onclick: { let id = v.id.clone(); move |_| *MODAL.write() = Some(Modal::EditVault(id.clone())) },
                            Icon { name: "edit", size: 16 }
                        }
                    }
                    button { class: "icon-btn", title: if v.is_owner { t("vault.delete") } else { t("vault.leave") },
                        onclick: { let id = v.id.clone(); move |_| *MODAL.write() = Some(Modal::DeleteVault(id.clone())) },
                        Icon { name: "trash", size: 16 }
                    }
                }
            }
            div { class: "settings-row",
                button { class: "btn small", onclick: move |_| *MODAL.write() = Some(Modal::NewVault), Icon { name: "plus", size: 14 } {t("vault.new")} }
            }
        }
    }
}

/// Extension: offer 2Secret for passkeys, or leave them to the browser.
#[component]
fn PasskeysRow() -> Element {
    let mut enabled = use_signal(|| true);
    use_hook(move || spawn(async move { enabled.set(crate::extension::passkeys_enabled().await) }));
    rsx! {
        div { class: "settings-row",
            div { class: "k",
                div { class: "t", {t("settings.passkeys")} }
                div { class: "d", {t("settings.passkeys_desc")} }
            }
            button { class: either(enabled(), "btn small", "btn small primary"),
                onclick: move |_| {
                    let on = !enabled();
                    enabled.set(on);
                    spawn(async move { crate::extension::set_passkeys_enabled(on).await });
                },
                {either(enabled(), t("common.turn_off"), t("common.turn_on"))}
            }
        }
    }
}

/// Turn unlocking with Touch ID / Face ID / Windows Hello on or off.
#[component]
fn BiometricRow() -> Element {
    let kind = use_hook(biometric::available);
    let mut enabled = use_signal(|| biometric_unlock().is_some());
    let Some(kind) = kind else { return rsx! {} };
    let toggle = move |_| {
        if enabled() {
            disable_biometric_unlock();
            enabled.set(false);
            toast(&with_kind(t("settings.biometric_off"), kind));
            return;
        }
        let Some((account_id, account_key)) =
            SESSION.peek().as_ref().map(|s| (s.account().id.clone(), s.account_key().clone()))
        else {
            return;
        };
        spawn(async move {
            let reason = t("settings.biometric_reason").to_string();
            let id = account_id.clone();
            match platform::run_heavy(move || biometric::create_device_key(&id, &reason)).await {
                Ok(device_key) => {
                    save_biometric_unlock(&BiometricUnlock::new(&account_id, &account_key, &device_key));
                    refresh_autofill();
                    enabled.set(true);
                    toast(&with_kind(t("settings.biometric_on"), kind));
                }
                Err(biometric::Error::Cancelled) => {}
                Err(biometric::Error::Unavailable) => toast_err(&with_kind(t("settings.biometric_unavailable"), kind)),
                Err(biometric::Error::Failed(msg)) => toast_err(&msg),
            }
        });
    };
    rsx! {
        div { class: "settings-row",
            div { class: "k",
                div { class: "t", {with_kind(t("settings.biometric"), kind)} }
                div { class: "d", {with_kind(t("settings.biometric_desc"), kind)} }
            }
            button { class: either(enabled(), "btn small", "btn small primary"), onclick: toggle,
                {either(enabled(), t("common.turn_off"), t("common.turn_on"))}
            }
        }
    }
}

/// Where to turn on AutoFill in Safari and other apps (iOS, and macOS builds
/// that include the extension).
#[component]
fn AutofillRow() -> Element {
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    if crate::apple_autofill::available() {
        let desc =
            t(if cfg!(target_os = "macos") { "settings.autofill_desc_macos" } else { "settings.autofill_desc_ios" });
        return rsx! {
            div { class: "settings-row",
                div { class: "k",
                    div { class: "t", {t("settings.autofill")} }
                    div { class: "d", {desc} }
                }
            }
        };
    }
    rsx! {}
}

/// Windows, Linux and the BSDs: whether `otpauth://` setup links open 2Secret
/// (`link_handler`).
#[cfg(all(feature = "desktop", not(target_os = "macos")))]
#[component]
fn SetupLinksRow() -> Element {
    use crate::link_handler::{handler, register, Handler};
    let mut ours = use_signal(|| None::<bool>);
    use_hook(move || {
        spawn(async move {
            let handler = crate::platform::run_heavy(handler).await;
            ours.set(Some(handler == Handler::TwoSecret));
        })
    });
    let make_default = move |_| {
        spawn(async move {
            if crate::platform::run_heavy(register).await {
                ours.set(Some(true));
                toast(t("settings.setup_links_on"));
            } else {
                toast_err(t("settings.setup_links_failed"));
            }
        });
    };
    rsx! {
        div { class: "settings-row",
            div { class: "k",
                div { class: "t", {t("settings.setup_links")} }
                div { class: "d", {t("settings.setup_links_desc")} }
            }
            match ours() {
                Some(true) => rsx! { span { class: "muted", {t("settings.setup_links_on")} } },
                Some(false) => rsx! { button { class: "btn small", onclick: make_default, {t("settings.setup_links_use")} } },
                None => rsx! {},
            }
        }
    }
}

/// macOS and iOS: 2Secret is chosen under *Set Up Codes In* in the system
/// settings; the web vault and Android open no setup links.
#[cfg(not(all(feature = "desktop", not(target_os = "macos"))))]
#[component]
fn SetupLinksRow() -> Element {
    rsx! {}
}

#[component]
fn SecuritySection() -> Element {
    let prefs = PREFS.read().clone();
    rsx! {
        div { class: "section",
            SectionTitle { text: t("settings.security") }
            div { class: "settings-row",
                div { class: "k",
                    div { class: "t", {t("settings.auto_lock")} }
                    div { class: "d", {t("settings.auto_lock_desc")} }
                }
                select { class: "input",
                    onchange: move |e| { if let Ok(n) = e.value().parse() { PREFS.write().auto_lock_minutes = n; save_prefs(); } },
                    for (m , label) in [(1u32, "1 min"), (5, "5 min"), (10, "10 min"), (30, "30 min"), (60, "1 h"), (240, "4 h"), (0, t("settings.never"))] {
                        option { key: "{m}", value: "{m}", selected: prefs.auto_lock_minutes == m, "{label}" }
                    }
                }
            }
            BiometricRow {}
            AutofillRow {}
            SetupLinksRow {}
            if crate::extension::ENABLED {
                PasskeysRow {}
            }
            div { class: "settings-row",
                div { class: "k",
                    div { class: "t", {t("settings.clipboard")} }
                    div { class: "d", {t("settings.clipboard_desc")} }
                }
                select { class: "input",
                    onchange: move |e| { if let Ok(n) = e.value().parse() { PREFS.write().clipboard_clear_secs = n; save_prefs(); } },
                    for (secs , label) in [(30u32, "30 s"), (60, "1 min"), (90, "90 s"), (180, "3 min"), (0, t("settings.never"))] {
                        option { key: "{secs}", value: "{secs}", selected: prefs.clipboard_clear_secs == secs, "{label}" }
                    }
                }
            }
            div { class: "settings-row",
                div { class: "k",
                    div { class: "t", {t("lock.lock_now")} }
                }
                button { class: "btn small", onclick: move |_| lock(), Icon { name: "lock", size: 15 } {t("lock.lock_now")} }
            }
        }
    }
}

#[component]
fn AppearanceSection() -> Element {
    let prefs = PREFS.read().clone();
    let current_lang = LANG();
    rsx! {
        div { class: "section",
            SectionTitle { text: t("settings.appearance") }
            div { class: "settings-row",
                div { class: "k", div { class: "t", {t("settings.language")} } }
                select { class: "input",
                    onchange: move |e| {
                        if let Some(l) = Lang::ALL.into_iter().find(|l| l.code() == e.value()) { set_lang(l); }
                    },
                    for l in Lang::ALL {
                        option { key: "{l.code()}", value: "{l.code()}", selected: l == current_lang, "{l.name()}" }
                    }
                }
            }
            div { class: "settings-row",
                div { class: "k", div { class: "t", {t("settings.theme")} } }
                select { class: "input",
                    onchange: move |e| {
                        PREFS.write().theme = match e.value().as_str() { "light" => Theme::Light, "dark" => Theme::Dark, _ => Theme::System };
                        save_prefs();
                    },
                    for (th , label) in [(Theme::System, t("settings.theme_system")), (Theme::Light, t("settings.theme_light")), (Theme::Dark, t("settings.theme_dark"))] {
                        option { key: "{th.id()}", value: "{th.id()}", selected: prefs.theme == th, "{label}" }
                    }
                }
            }
            if !crate::extension::ENABLED {
                div { class: "settings-row",
                    div { class: "k",
                        div { class: "t", {t("settings.start_screen")} }
                        div { class: "d", {t("settings.start_screen_desc")} }
                    }
                    select { class: "input",
                        onchange: move |e| {
                            if let Some(start) = StartScreen::ALL.into_iter().find(|s| s.id() == e.value()) {
                                PREFS.write().start_screen = start;
                                save_prefs();
                            }
                        },
                        for start in StartScreen::ALL {
                            option { key: "{start.id()}", value: "{start.id()}", selected: prefs.start_screen == start,
                                {nav_title(&start.nav())}
                            }
                        }
                    }
                }
            }
            if FETCHES_ICONS {
                WebsiteIconsRow {}
            }
        }
    }
}

/// Fetch website icons (on by default), also for the logins already there.
#[component]
fn WebsiteIconsRow() -> Element {
    let on = PREFS.read().website_icons;
    let fetch_all = move |_| {
        let ids: Vec<String> = SESSION
            .peek()
            .as_ref()
            .map(|s| s.all_items().map(|(_, item)| item.id.clone()).collect())
            .unwrap_or_default();
        fetch_icons(ids);
        toast(t("settings.website_icons_started"));
    };
    rsx! {
        div { class: "settings-row",
            div { class: "k",
                div { class: "t", {t("settings.website_icons")} }
                div { class: "d", {t("settings.website_icons_desc")} }
            }
            if on {
                button { class: "btn small", onclick: fetch_all, {t("settings.website_icons_all")} }
            }
            button { class: either(on, "btn small", "btn small primary"),
                onclick: move |_| {
                    PREFS.write().website_icons = !on;
                    save_prefs();
                },
                {either(on, t("common.turn_off"), t("common.turn_on"))}
            }
        }
    }
}

#[component]
fn ImportSection() -> Element {
    let mut file = use_signal(|| None::<(String, Vec<u8>)>);
    let mut format = use_signal(|| None::<ImportFormat>);
    let mut target = use_signal(|| "auto".to_string());
    let mut password = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let vaults = SESSION.read().as_ref().map(|s| s.vaults()).unwrap_or_default();
    let needs_password = file().as_ref().is_some_and(|(_, d)| {
        twosecret_core::crypto::PasswordEnvelope::is_envelope(&String::from_utf8_lossy(&d[..d.len().min(4096)]))
    });

    let run_import = move |_| {
        let Some((name, data)) = file() else { return };
        let fmt = format().or_else(|| import::detect(&name, &data));
        let Some(fmt) = fmt else {
            error.set(Some(t("import.unknown_format").into()));
            return;
        };
        let pw = password();
        let tgt = target();
        error.set(None);
        spawn(async move {
            busy(t("busy.importing"));
            let parsed = platform::run_heavy(move || {
                import::import(&data, fmt, if pw.is_empty() { None } else { Some(pw.as_str()) })
            })
            .await;
            unbusy();
            match parsed {
                Ok(result) => {
                    let warnings = result.warnings.len();
                    let target = if tgt == "auto" { None } else { Some(tgt) };
                    if let Some(summary) = mutate(move |s| s.import(result, target.as_deref())) {
                        toast(&format!(
                            "{} {} · {} {}",
                            summary.imported,
                            t("import.imported"),
                            summary.skipped_duplicates,
                            t("import.duplicates")
                        ));
                        if warnings > 0 {
                            toast_err(&format!("{warnings} {}", t("import.warnings")));
                        }
                        file.set(None);
                        password.set(String::new());
                    }
                }
                Err(e) => error.set(Some(core_error(&e))),
            }
        });
    };

    rsx! {
        div { class: "section",
            SectionTitle { text: t("settings.import") }
            div { class: "section-body",
                p { class: "small muted", {t("import.desc")} }
                if let Some(err) = error() { div { class: "error-box", "{err}" } }
                div { class: "form-group",
                    input { r#type: "file", accept: ".csv,.json,.1pux,.xml,.txt",
                        onchange: move |e| {
                            let files = e.files();
                            spawn(async move {
                                if let Some(f) = files.into_iter().next() {
                                    match f.read_bytes().await {
                                        Ok(b) => file.set(Some((f.name(), b.to_vec()))),
                                        Err(err) => toast_err(&err.to_string()),
                                    }
                                }
                            });
                        }
                    }
                }
                if let Some((name, data)) = file() {
                    div { class: "form-group",
                        label { class: "label", {t("import.format")} }
                        select { class: "input",
                            onchange: move |e| format.set(ImportFormat::parse(&e.value())),
                            option { value: "auto", selected: format().is_none(),
                                "{t(\"import.auto\")}" if let Some(d) = import::detect(&name, &data) { ": {d.name()}" }
                            }
                            for f in ImportFormat::ALL {
                                option { key: "{f.id()}", value: "{f.id()}", selected: format() == Some(f), "{f.name()}" }
                            }
                        }
                    }
                    div { class: "form-group",
                        label { class: "label", {t("import.target")} }
                        select { class: "input", onchange: move |e| target.set(e.value()),
                            option { value: "auto", {t("import.target_auto")} }
                            for v in vaults.iter().filter(|v| v.role.can_write()) {
                                option { key: "{v.id}", value: "{v.id}", "{v.name}" }
                            }
                        }
                    }
                    if needs_password {
                        div { class: "form-group",
                            label { class: "label", {t("import.password")} }
                            PasswordInput { value: password(), oninput: move |v| password.set(v) }
                        }
                    }
                    button { class: "btn primary", onclick: run_import, Icon { name: "upload", size: 15 } {t("import.run")} }
                }
            }
        }
    }
}

/// Encrypted backups (with a reminder) and readable exports.
#[component]
fn ExportSection() -> Element {
    let mut format = use_signal(|| "encrypted".to_string());
    let mut password = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let mut reset = use_signal(|| 0u32);
    let mut error = use_signal(|| None::<String>);
    let prefs = PREFS.read().clone();
    let last =
        if prefs.last_backup_at > 0 { relative_time(prefs.last_backup_at) } else { t("backup.never").to_string() };
    let run_export = move |_| {
        let fmt = format();
        let (pw, cf) = (password(), confirm());
        if fmt == "encrypted" {
            if let Err(e) = check_backup_password(&pw, &cf) {
                error.set(Some(e));
                return;
            }
        }
        error.set(None);
        spawn(async move {
            match save_backup(&fmt, pw).await {
                Ok(w) => {
                    toast(&format!("{} {w}", t("toast.saved_to")));
                    password.set(String::new());
                    confirm.set(String::new());
                    reset += 1;
                }
                Err(e) => error.set(Some(e)),
            }
        });
    };
    rsx! {
        div { class: "section",
            SectionTitle { text: t("settings.export") }
            div { class: "settings-row",
                div { class: "k",
                    div { class: "t", {t("backup.last")} }
                    div { class: "d", "{last}" }
                }
            }
            div { class: "settings-row",
                div { class: "k",
                    div { class: "t", {t("backup.remind")} }
                    div { class: "d", {t("backup.remind_desc")} }
                }
                select { class: "input",
                    onchange: move |e| { if let Ok(n) = e.value().parse() { PREFS.write().backup_reminder_days = n; save_prefs(); } },
                    for (days , label) in [(14u32, t("backup.every_2_weeks")), (30, t("backup.every_month")), (90, t("backup.every_3_months")), (0, t("settings.never"))] {
                        option { key: "{days}", value: "{days}", selected: prefs.backup_reminder_days == days, "{label}" }
                    }
                }
            }
            div { class: "section-body",
                p { class: "small muted", style: "margin-top:0;line-height:1.5", {t("backup.explain")} }
                if let Some(err) = error() { div { class: "error-box", "{err}" } }
                div { class: "form-group",
                    select { class: "input", onchange: move |e| format.set(e.value()),
                        option { value: "encrypted", selected: format() == "encrypted", {t("export.encrypted")} }
                        option { value: "json", selected: format() == "json", {t("export.json")} }
                        option { value: "csv", selected: format() == "csv", {t("export.csv")} }
                    }
                }
                if format() == "encrypted" {
                    div { class: "form-group",
                        label { class: "label", {t("export.password")} }
                        PasswordInput { value: password(), oninput: move |v| password.set(v), reset: reset() }
                    }
                    div { class: "form-group",
                        label { class: "label", {t("create.confirm")} }
                        PasswordInput { value: confirm(), oninput: move |v| confirm.set(v), reset: reset() }
                    }
                } else {
                    div { class: "warn-box small", {t("export.plain_warning")} }
                }
                button { class: "btn", onclick: run_export, Icon { name: "download", size: 15 } {t("export.run")} }
            }
        }
    }
}

/// A backup password must be at least 8 characters and typed twice the same.
pub fn check_backup_password(password: &str, confirm: &str) -> Result<(), String> {
    if password.chars().count() < 8 {
        Err(t("create.err_short").into())
    } else if password != confirm {
        Err(t("create.err_mismatch").into())
    } else {
        Ok(())
    }
}

#[component]
fn UpdatesSection() -> Element {
    use crate::updater::{self, Mode, Status, STATUS};
    let mode = use_hook(updater::mode);
    if mode == Mode::Off {
        return rsx! {};
    }
    let auto = PREFS.read().auto_update;
    let status = STATUS.read().clone();
    let version = twosecret_core::VERSION;
    let with_version = |key: &str, v: &str| t(key).replace("{version}", v);
    let text = match &status {
        Status::Idle => t("update.idle").to_string(),
        Status::Checking => t("update.checking").to_string(),
        Status::UpToDate => t("update.up_to_date").to_string(),
        Status::Available { version, installable: true, .. } => with_version("update.available", version),
        Status::Available { version, .. } => {
            format!("{} {}", with_version("update.available", version), t("update.manual"))
        }
        Status::Downloading { version } => with_version("update.downloading", version),
        Status::Ready { version, .. } => with_version("update.ready", version),
        Status::Failed(e) => format!("{} {e}", t("update.failed")),
    };
    let notes = match &status {
        Status::Available { notes, .. } | Status::Ready { notes, .. } => Some(notes.clone()),
        _ => None,
    };
    let toggle = move |_| {
        let on = !PREFS.peek().auto_update;
        PREFS.write().auto_update = on;
        save_prefs();
        if on {
            spawn(updater::check(true));
        }
    };
    let (auto_title, auto_desc) = match mode {
        Mode::Install => (t("update.auto_install"), t("update.auto_install_desc")),
        _ => (t("update.auto_notify"), t("update.auto_notify_desc")),
    };
    rsx! {
        div { class: "section",
            SectionTitle { text: t("update.title") }
            div { class: "settings-row",
                div { class: "k",
                    div { class: "t", "2Secret {version}" }
                    div { class: "d", "{text}" }
                    if let Some(url) = notes {
                        div { class: "d",
                            a { href: "#", onclick: move |e| { e.prevent_default(); platform::open_url(&url); }, {t("update.whats_new")} }
                        }
                    }
                }
                match status {
                    Status::Available { installable: true, .. } => rsx! {
                        button { class: "btn small primary", onclick: move |_| { spawn(updater::install()); }, Icon { name: "download", size: 15 } {t("update.install")} }
                    },
                    Status::Available { download, .. } => rsx! {
                        button { class: "btn small primary", onclick: move |_| platform::open_url(&download), Icon { name: "download", size: 15 } {t("update.download")} }
                    },
                    Status::Ready { .. } => rsx! {
                        button { class: "btn small primary", onclick: move |_| updater::restart(), {t("update.restart")} }
                    },
                    Status::Checking | Status::Downloading { .. } => rsx! {
                        button { class: "btn small", disabled: true, {t("update.check")} }
                    },
                    _ => rsx! {
                        button { class: "btn small", onclick: move |_| { spawn(updater::check(false)); }, {t("update.check")} }
                    },
                }
            }
            div { class: "settings-row",
                div { class: "k",
                    div { class: "t", {auto_title} }
                    div { class: "d", {auto_desc} }
                }
                button { class: either(auto, "btn small", "btn small primary"), onclick: toggle,
                    {either(auto, t("common.turn_off"), t("common.turn_on"))}
                }
            }
        }
    }
}

#[component]
fn AboutSection() -> Element {
    let version = twosecret_core::VERSION;
    let platform_name = match platform::kind() {
        platform::Kind::Desktop => std::env::consts::OS,
        platform::Kind::Web => "web",
        platform::Kind::Mobile => "mobile",
    };
    rsx! {
        div { class: "section",
            SectionTitle { text: t("settings.about") }
            div { class: "section-body",
                p { style: "margin-top:0", strong { "2Secret {version}" } " · {platform_name}" }
                InstallLocation {}
                p { class: "small muted", style: "line-height:1.6", {t("about.text")} }
                p { class: "small",
                    a { href: "#", onclick: move |e| { e.prevent_default(); platform::open_url("https://github.com/joostiphone/2Secret"); }, "github.com/joostiphone/2Secret" }
                    " · MIT / Apache-2.0"
                }
            }
        }
    }
}

/// Desktop: where this 2Secret is installed, so a second installation (the
/// Windows setup next to the MSI, say) shows which one runs.
#[component]
fn InstallLocation() -> Element {
    #[cfg(feature = "desktop")]
    if let Some(location) = install_location() {
        // Windows: the MSI installs into Program Files for everyone, the
        // setup into the user's folder, where 2Secret can update itself.
        #[cfg(windows)]
        let kind = {
            let program_files = std::env::var("ProgramFiles").unwrap_or_default().to_lowercase();
            let msi = !program_files.is_empty() && location.to_lowercase().starts_with(&program_files);
            format!(" · {}", t(if msi { "about.install_msi" } else { "about.install_setup" }))
        };
        #[cfg(not(windows))]
        let kind = String::new();
        return rsx! {
            p { class: "small muted", style: "overflow-wrap:anywhere",
                {t("about.installed_in")} " " span { class: "mono", "{location}" } "{kind}"
            }
        };
    }
    rsx! {}
}

/// The program's folder on Windows, the app bundle on macOS, the AppImage
/// or the program on Linux and the BSDs.
#[cfg(feature = "desktop")]
fn install_location() -> Option<String> {
    if let Some(appimage) = std::env::var_os("APPIMAGE").filter(|_| cfg!(target_os = "linux")) {
        return Some(std::path::PathBuf::from(appimage).display().to_string());
    }
    let exe = std::env::current_exe().ok()?;
    let location = if cfg!(windows) {
        exe.parent()?.to_path_buf()
    } else if cfg!(target_os = "macos") {
        exe.ancestors().find(|p| p.extension().is_some_and(|e| e == "app")).unwrap_or(&exe).to_path_buf()
    } else {
        exe
    };
    Some(location.display().to_string())
}

#[component]
fn DangerSection() -> Element {
    let mut deleting = use_signal(|| false);
    let mut password = use_signal(String::new);
    let linked = SESSION.read().as_ref().is_some_and(|s| s.server().is_some() && s.server_token().is_some());
    let delete_account = move |_| {
        let pw = password();
        let (Some(session), Some(sk)) = (session_copy(), secret_key()) else { return };
        spawn(async move {
            busy(t("busy.working"));
            let (mut session, keys) = platform::run_heavy(move || {
                let k = session.verify_password(&pw, &sk);
                (session, k)
            })
            .await;
            let result = match keys {
                Ok(k) => twosecret_client::delete_server_account_with_keys(&mut session, &k)
                    .await
                    .map_err(|e| client_error(&e)),
                Err(e) => Err(core_error(&e)),
            };
            unbusy();
            match result {
                Ok(()) => {
                    install_session(session);
                    deleting.set(false);
                    toast(t("toast.account_deleted"));
                }
                Err(e) => toast_err(&e),
            }
        });
    };
    rsx! {
        div { class: "section",
            SectionTitle { text: t("settings.danger") }
            if linked {
                div { class: "settings-row",
                    div { class: "k",
                        div { class: "t", {t("settings.delete_account")} }
                        div { class: "d", {t("settings.delete_account_desc")} }
                    }
                    button { class: "btn small danger", onclick: move |_| deleting.toggle(), {t("common.delete")} }
                }
                if deleting() {
                    div { class: "section-body",
                        div { class: "form-group",
                            label { class: "label", {t("common.master_password")} }
                            PasswordInput { value: password(), oninput: move |v| password.set(v) }
                        }
                        button { class: "btn danger", onclick: delete_account, {t("settings.delete_account_confirm")} }
                    }
                }
            }
            div { class: "settings-row",
                div { class: "k",
                    div { class: "t", {t("settings.forget")} }
                    div { class: "d", {t("settings.forget_desc")} }
                }
                button { class: "btn small danger", onclick: move |_| *MODAL.write() = Some(Modal::ForgetDevice), {t("settings.forget_button")} }
            }
        }
    }
}
