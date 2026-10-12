//! Welcome, account creation, sign-in, Secret Key and lock screens.

use dioxus::prelude::*;
use twosecret_core::crypto::{derive_keys, KdfParams, SecretKey};
use twosecret_core::session::{check_master_password, PasswordProblem, Session};

use crate::biometric;
use crate::components::widgets::*;
use crate::i18n::t;
use crate::icons::Icon;
use crate::platform;
use crate::state::*;
use twosecret_core::profile::PROFILE_KEY;

#[component]
pub fn Welcome() -> Element {
    rsx! {
        div { class: "onboarding",
            div { class: "card",
                Brand { subtitle: t("welcome.tagline") }
                h2 { {t("welcome.title")} }
                p { class: "lead", {t("welcome.lead")} }
                button { class: "choice", onclick: move |_| *PHASE.write() = Phase::Create,
                    Icon { name: "plus", size: 22 }
                    div {
                        div { class: "t", {t("welcome.create")} }
                        div { class: "d", {t("welcome.create_desc")} }
                    }
                }
                button { class: "choice", onclick: move |_| *PHASE.write() = Phase::SignIn,
                    Icon { name: "cloud", size: 22 }
                    div {
                        div { class: "t", {t("welcome.signin")} }
                        div { class: "d", {t("welcome.signin_desc")} }
                    }
                }
                LangSwitch {}
            }
        }
    }
}

#[component]
pub fn CreateAccount() -> Element {
    let mut name = use_signal(String::new);
    let mut email = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let default_server = platform::default_server();
    let mut use_server = use_signal(|| default_server.is_some());
    let mut server = use_signal(move || default_server.clone().unwrap_or_default());
    let mut invite = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);

    let submit = move |_| {
        let (n, e, pw, c) = (name(), email(), password(), confirm());
        let validation = if n.trim().is_empty() {
            Some(t("create.err_name"))
        } else if !e.contains('@') {
            Some(t("create.err_email"))
        } else if let Err(problem) = check_master_password(&pw, &[&n, &e]) {
            Some(match problem {
                PasswordProblem::TooShort => t("create.err_short"),
                PasswordProblem::TooWeak => t("create.err_weak"),
            })
        } else if pw != c {
            Some(t("create.err_mismatch"))
        } else if use_server() && server().trim().is_empty() {
            Some(t("create.err_server"))
        } else {
            None
        };
        if let Some(msg) = validation {
            error.set(Some(msg.to_string()));
            return;
        }
        error.set(None);
        let srv = if use_server() { Some(server()) } else { None };
        let inv = invite();
        spawn(async move {
            busy(t("busy.creating"));
            let vault_name = t("vault.personal").to_string();
            let pw2 = pw.clone();
            let created = platform::run_heavy(move || {
                Session::create_account_with_keys(&n, &e, &pw2, KdfParams::default(), &vault_name)
            })
            .await;
            let (mut session, sk, keys) = match created {
                Ok(v) => v,
                Err(err) => {
                    unbusy();
                    error.set(Some(core_error(&err)));
                    return;
                }
            };
            if let Some(url) = srv {
                busy(t("busy.registering"));
                let inv = if inv.trim().is_empty() { None } else { Some(inv.trim().to_string()) };
                if let Err(err) = twosecret_client::connect_with_keys(
                    &mut session,
                    &url,
                    &keys,
                    inv.as_deref(),
                    &platform::device_name(),
                )
                .await
                {
                    unbusy();
                    error.set(Some(client_error(&err)));
                    return;
                }
            }
            unbusy();
            let formatted = sk.formatted();
            match adopt_session(session, &sk) {
                Ok(()) => *PHASE.write() = Phase::NewAccount { secret_key: formatted },
                Err(msg) => error.set(Some(msg)),
            }
        });
    };

    rsx! {
        div { class: "onboarding",
            div { class: "card",
                Brand {}
                h2 { {t("create.title")} }
                p { class: "lead", {t("create.lead")} }
                if let Some(err) = error() {
                    div { class: "error-box", "{err}" }
                }
                div { class: "form-group",
                    label { class: "label", {t("create.name")} }
                    input { class: "input", initial_value: "{name}", autofocus: true, onmounted: focus_on_mount, oninput: move |e| name.set(e.value()) }
                }
                div { class: "form-group",
                    label { class: "label", {t("common.email")} }
                    input { class: "input", r#type: "email", initial_value: "{email}", autocapitalize: "off", oninput: move |e| email.set(e.value()) }
                }
                div { class: "form-group",
                    label { class: "label", {t("common.master_password")} }
                    PasswordInput { value: password(), oninput: move |v| password.set(v) }
                    StrengthMeter { password: password(), inputs: vec![name(), email()] }
                    div { class: "small muted", style: "margin-top:6px", {t("create.password_hint")} }
                }
                div { class: "form-group",
                    label { class: "label", {t("create.confirm")} }
                    PasswordInput { value: confirm(), oninput: move |v| confirm.set(v) }
                }
                div { class: "form-group",
                    label { class: "checkbox",
                        input { r#type: "checkbox", checked: use_server(), onchange: move |e| use_server.set(e.checked()) }
                        span { {t("create.use_server")} }
                    }
                }
                if use_server() {
                    div { class: "form-group",
                        label { class: "label", {t("common.server")} }
                        input { class: "input", initial_value: "{server}", placeholder: "https://vault.example.com", autocapitalize: "off",
                            oninput: move |e| server.set(e.value()) }
                    }
                    div { class: "form-group",
                        label { class: "label", {t("create.invite")} }
                        input { class: "input", initial_value: "{invite}", placeholder: t("common.optional"), oninput: move |e| invite.set(e.value()) }
                    }
                } else {
                    div { class: "info-box small", {t("create.local_info")} }
                }
                button { class: "btn primary block", onclick: submit, {t("create.submit")} }
                div { class: "center", style: "margin-top:14px",
                    button { class: "btn ghost", onclick: move |_| *PHASE.write() = Phase::Welcome,
                        Icon { name: "chevron-left", size: 16 }
                        {t("common.back")}
                    }
                }
            }
        }
    }
}

#[component]
pub fn SignIn() -> Element {
    let mut server = use_signal(|| platform::default_server().unwrap_or_default());
    let mut email = use_signal(String::new);
    let mut sk_text = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);

    let mut submit = move || {
        let (srv, mail, pw) = (server(), email(), password());
        if srv.trim().is_empty() || !mail.contains('@') || pw.is_empty() {
            error.set(Some(t("signin.err_fields").to_string()));
            return;
        }
        let sk = match SecretKey::parse(&sk_text()) {
            Ok(sk) => sk,
            Err(e) => {
                error.set(Some(core_error(&e)));
                return;
            }
        };
        error.set(None);
        spawn(async move {
            busy(t("busy.signing_in"));
            let pre = match twosecret_client::prelogin(&srv, &mail).await {
                Ok(p) => p,
                Err(e) => {
                    unbusy();
                    error.set(Some(client_error(&e)));
                    return;
                }
            };
            let salt = twosecret_core::util::unb64(&pre.salt).unwrap_or_default();
            let (pw2, sk2, mail2) = (pw.clone(), sk.clone(), mail.clone());
            let keys = platform::run_heavy(move || derive_keys(&pw2, &sk2, &mail2, &salt, &pre.kdf)).await;
            let keys = match keys {
                Ok(k) => k,
                Err(e) => {
                    unbusy();
                    error.set(Some(core_error(&e)));
                    return;
                }
            };
            busy(t("busy.downloading"));
            match twosecret_client::signin_with_keys(&srv, &mail, &keys, &platform::device_name()).await {
                Ok(session) => {
                    unbusy();
                    match adopt_session(session, &sk) {
                        Ok(()) => *PHASE.write() = Phase::Unlocked,
                        Err(msg) => error.set(Some(msg)),
                    }
                }
                Err(e) => {
                    unbusy();
                    error.set(Some(client_error(&e)));
                }
            }
        });
    };

    rsx! {
        div { class: "onboarding",
            div { class: "card",
                Brand {}
                h2 { {t("signin.title")} }
                p { class: "lead", {t("signin.lead")} }
                if let Some(err) = error() {
                    div { class: "error-box", "{err}" }
                }
                div { class: "form-group",
                    label { class: "label", {t("common.server")} }
                    input { class: "input", initial_value: "{server}", placeholder: "https://vault.example.com", autocapitalize: "off",
                        oninput: move |e| server.set(e.value()) }
                }
                div { class: "form-group",
                    label { class: "label", {t("common.email")} }
                    input { class: "input", r#type: "email", initial_value: "{email}", autocapitalize: "off", oninput: move |e| email.set(e.value()) }
                }
                div { class: "form-group",
                    label { class: "label", {t("common.secret_key")} }
                    input { class: "input mono", initial_value: "{sk_text}", placeholder: "2S-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXXX",
                        autocapitalize: "characters", spellcheck: "false", oninput: move |e| sk_text.set(e.value()) }
                }
                div { class: "form-group",
                    label { class: "label", {t("common.master_password")} }
                    PasswordInput { value: password(), oninput: move |v| password.set(v), onenter: move |_| submit() }
                }
                button { class: "btn primary block", onclick: move |_| submit(), {t("signin.submit")} }
                div { class: "center", style: "margin-top:14px",
                    button { class: "btn ghost", onclick: move |_| *PHASE.write() = Phase::Welcome,
                        Icon { name: "chevron-left", size: 16 }
                        {t("common.back")}
                    }
                }
            }
        }
    }
}

#[component]
pub fn NewAccount(secret_key: String) -> Element {
    let mut saved = use_signal(|| false);
    let sk_for_copy = secret_key.clone();
    let sk_for_kit = secret_key.clone();
    let download = move |_| {
        let Some((name, email, server)) = SESSION
            .peek()
            .as_ref()
            .map(|s| (s.account().name.clone(), s.account().email.clone(), s.server().map(|l| l.url.clone())))
        else {
            return;
        };
        let Ok(sk) = SecretKey::parse(&sk_for_kit) else { return };
        let html = twosecret_core::emergency_kit::html(&name, &email, server.as_deref(), &sk);
        spawn(async move {
            match platform::save_file("2Secret-Emergency-Kit.html", "text/html", html.as_bytes()).await {
                Ok(where_) => {
                    toast(&format!("{} {where_}", t("toast.saved_to")));
                    saved.set(true);
                }
                Err(e) => toast_err(&e),
            }
        });
    };
    rsx! {
        div { class: "onboarding",
            div { class: "card wide",
                Brand {}
                h2 { {t("newacc.title")} }
                p { class: "lead", {t("newacc.lead")} }
                div { class: "secret-key", "{secret_key}" }
                div { class: "row wrap", style: "margin-bottom:16px",
                    button { class: "btn primary", onclick: download,
                        Icon { name: "download", size: 16 }
                        {t("newacc.download_kit")}
                    }
                    button { class: "btn", onclick: move |_| copy(sk_for_copy.clone(), t("common.secret_key")),
                        Icon { name: "copy", size: 16 }
                        {t("common.copy")}
                    }
                }
                div { class: "warn-box small", {t("newacc.warning")} }
                label { class: "checkbox", style: "margin-bottom:16px",
                    input { r#type: "checkbox", checked: saved(), onchange: move |e| saved.set(e.checked()) }
                    span { {t("newacc.confirm")} }
                }
                button { class: "btn primary block", disabled: !saved(),
                    onclick: move |_| {
                        *PHASE.write() = Phase::Unlocked;
                        request_sync();
                    },
                    {t("newacc.continue")}
                }
            }
        }
    }
}

/// Ask for Touch ID / Face ID / Windows Hello by itself only on the first
/// lock screen after the app starts, not after every auto-lock.
static BIOMETRIC_PROMPTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn finish_unlock(session: Session) {
    *SESSION.write() = Some(session);
    *PHASE.write() = Phase::Unlocked;
    touch();
    remember_unlock();
    request_sync();
}

#[component]
pub fn LockScreen() -> Element {
    let profile = use_hook(load_profile);
    let mut password = use_signal(String::new);
    let mut reset = use_signal(|| 0u32);
    let mut error = use_signal(|| None::<String>);
    let bio_config = use_hook(biometric_unlock);
    let bio_kind = use_hook(|| bio_config.as_ref().and_then(|_| biometric::available()));
    let password_needed = bio_config.as_ref().is_some_and(|c| c.password_required());
    let bio_ready = bio_kind.filter(|_| !password_needed);

    let mut unlock_biometric = move || {
        let (Some(kind), Some(profile), Some(config)) = (bio_ready, load_profile(), biometric_unlock()) else {
            return;
        };
        error.set(None);
        spawn(async move {
            let reason = t("lock.biometric_reason").to_string();
            let account_id = config.account_id.clone();
            let device_key = platform::run_heavy(move || biometric::device_key(&account_id, &reason)).await;
            let result = match device_key {
                Ok(key) => platform::run_heavy(move || {
                    config.account_key(&key).and_then(|ak| Session::open_with_account_key(profile, ak))
                })
                .await
                .map_err(|e| core_error(&e)),
                Err(biometric::Error::Cancelled) => return,
                Err(biometric::Error::Unavailable) => Err(with_kind(t("lock.biometric_unavailable"), kind)),
                Err(biometric::Error::Failed(msg)) => Err(msg),
            };
            match result {
                Ok(session) => finish_unlock(session),
                Err(msg) => error.set(Some(msg)),
            }
        });
    };
    use_hook(move || {
        if bio_ready.is_some() && !BIOMETRIC_PROMPTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            unlock_biometric();
        }
    });
    let (name, email) = profile.as_ref().map(|p| (p.account.name.clone(), p.account.email.clone())).unwrap_or_default();
    let initial: String = name.chars().next().map(|c| c.to_uppercase().collect()).unwrap_or_else(|| "?".into());

    let mut unlock = move || {
        let pw = password();
        if pw.is_empty() {
            return;
        }
        let (Some(profile), Some(sk)) = (load_profile(), secret_key()) else {
            error.set(Some(t("err.no_account").to_string()));
            return;
        };
        error.set(None);
        spawn(async move {
            busy(t("busy.unlocking"));
            let linked = profile.server.is_some();
            let (pw2, profile2) = (pw.clone(), profile.clone());
            let mut result =
                platform::run_heavy(move || Session::unlock(profile, &pw, &sk)).await.map_err(|e| core_error(&e));
            if linked && result.is_err() {
                // The password may have been changed on another device.
                result = unlock_online(profile2, pw2).await;
                if let Ok(session) = &result {
                    let _ = platform::storage().write(PROFILE_KEY, &session.profile().to_json());
                }
            }
            unbusy();
            match result {
                Ok(session) => {
                    password.set(String::new());
                    finish_unlock(session);
                    password_entered();
                }
                Err(msg) => {
                    password.set(String::new());
                    reset += 1;
                    error.set(Some(msg));
                }
            }
        });
    };

    rsx! {
        div { class: "onboarding",
            div { class: "card center",
                div { class: "lock-avatar", "{initial}" }
                h2 { "{name}" }
                p { class: "lead", "{email}" }
                if let Some(request) = PASSKEY.read().as_ref() {
                    div { class: "info-box small", {t("passkey.waiting").replace("{site}", &request.origin)} }
                }
                if let Some(err) = error() {
                    div { class: "error-box", "{err}" }
                } else if password_needed {
                    div { class: "info-box small", {t("lock.biometric_password_needed")} }
                }
                if let Some(kind) = bio_ready {
                    button { class: "btn block", style: "margin-bottom:16px", onclick: move |_| unlock_biometric(),
                        Icon { name: "shield", size: 16 }
                        {with_kind(t("lock.biometric"), kind)}
                    }
                }
                div { class: "form-group", style: "text-align:left",
                    PasswordInput {
                        value: password(),
                        oninput: move |v| password.set(v),
                        placeholder: t("common.master_password"),
                        autofocus: true,
                        reset: reset(),
                        onenter: move |_| unlock(),
                    }
                }
                button { class: "btn primary block", onclick: move |_| unlock(),
                    Icon { name: "lock", size: 16 }
                    {t("lock.unlock")}
                }
                div { style: "margin-top:16px",
                    button { class: "btn ghost small", onclick: move |_| *MODAL.write() = Some(Modal::ForgetDevice),
                        {t("lock.other_account")}
                    }
                }
                LangSwitch {}
            }
        }
    }
}
