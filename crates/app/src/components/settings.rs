//! Settings: account, sync, security, appearance, import/export and more.

use dioxus::prelude::*;
use twosecret_core::api::DeviceInfo;
use twosecret_core::import::{self, ImportFormat};

use crate::components::shell::relative_time;
use crate::components::widgets::*;
use crate::i18n::{t, Lang, LANG};
use crate::icons::{either, Icon};
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
                AboutSection {}
                DangerSection {}
            }
        }
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
                div { class: "k",
                    div { class: "t", "{account.name}" }
                    div { class: "d", "{account.email}" }
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
    let mut server = use_signal(|| platform::default_server().unwrap_or_default());
    let mut invite = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let submit = move |_| {
        let (url, inv, pw) = (server(), invite(), password());
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
            div { class: "form-group",
                label { class: "label", {t("common.server")} }
                input { class: "input", initial_value: "{server}", placeholder: "https://vault.example.com", autocapitalize: "off", oninput: move |e| server.set(e.value()) }
            }
            div { class: "form-group",
                label { class: "label", {t("create.invite")} }
                input { class: "input", initial_value: "{invite}", placeholder: t("common.optional"), oninput: move |e| invite.set(e.value()) }
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
                    Icon { name: either(v.is_shared(), "users", "vault"), size: 18 }
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

#[component]
fn ExportSection() -> Element {
    let mut format = use_signal(|| "encrypted".to_string());
    let mut password = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let mut reset = use_signal(|| 0u32);
    let mut error = use_signal(|| None::<String>);
    let run_export = move |_| {
        let fmt = format();
        let (pw, cf) = (password(), confirm());
        if fmt == "encrypted" {
            if pw.chars().count() < 8 {
                error.set(Some(t("create.err_short").into()));
                return;
            }
            if pw != cf {
                error.set(Some(t("create.err_mismatch").into()));
                return;
            }
        }
        let Some(data) = SESSION.peek().as_ref().map(|s| s.export(None, false)) else { return };
        error.set(None);
        spawn(async move {
            busy(t("busy.exporting"));
            let date = twosecret_core::util::format_date(twosecret_core::util::now());
            let (name, mime, content) = match fmt.as_str() {
                "json" => (format!("2Secret-export-{date}.json"), "application/json", Ok(data.to_json())),
                "csv" => (format!("2Secret-export-{date}.csv"), "text/csv", data.to_csv().map_err(|e| e.to_string())),
                _ => {
                    let r = platform::run_heavy(move || data.to_encrypted(&pw).map_err(|e| e.to_string())).await;
                    (format!("2Secret-backup-{date}.json"), "application/json", r)
                }
            };
            let result = match content {
                Ok(c) => platform::save_file(&name, mime, c.as_bytes()).await,
                Err(e) => Err(e),
            };
            unbusy();
            match result {
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
            div { class: "section-body",
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
                p { class: "small muted", style: "line-height:1.6", {t("about.text")} }
                p { class: "small",
                    a { href: "#", onclick: move |e| { e.prevent_default(); platform::open_url("https://github.com/joostiphone/2Secret"); }, "github.com/joostiphone/2Secret" }
                    " · MIT / Apache-2.0"
                }
            }
        }
    }
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
