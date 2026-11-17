//! A website asks for a passkey: through the browser extension, which opened
//! this window, or through Windows (`windows_passkeys`), which called the
//! desktop app.

use dioxus::prelude::*;
use twosecret_core::passkey::{
    self, CreationOptions, Passkey, RequestOptions, SystemCreation, SystemRequest, SystemSignIn, ES256,
};

use crate::components::widgets::*;
use crate::extension::{self, PasskeyAnswer, PasskeyRequest};
use crate::i18n::t;
use crate::icons::Icon;
use crate::state::*;
use crate::windows_passkeys::{self, Outcome, Refusal, Unverified};

/// Answer the page; the window closes itself.
fn answer(rid: String, answer: PasskeyAnswer) {
    *PASSKEY.write() = None;
    dioxus::core::spawn_forever(async move { extension::answer_passkey(&rid, answer).await });
}

/// Answer Windows, which passes it on to the website or app.
fn answer_windows(rid: &str, outcome: Outcome) {
    *PASSKEY.write() = None;
    windows_passkeys::answer(rid, outcome);
}

#[component]
pub fn PasskeyPrompt() -> Element {
    let Some(request) = PASSKEY.read().clone() else { return rsx! {} };
    let subtitle = request.origin.clone();
    let body = match request.system.clone() {
        Some(system) => match system.request {
            SystemRequest::Create(creation) => {
                rsx! { CreateForWindows { rid: request.rid.clone(), creation, verify: system.verify_user } }
            }
            SystemRequest::SignIn(sign_in) => {
                rsx! { UseForWindows { rid: request.rid.clone(), sign_in, verify: system.verify_user } }
            }
        },
        None if request.kind == "create" => rsx! { CreatePasskey { request } },
        None => rsx! { UsePasskey { request } },
    };
    rsx! {
        div { class: "onboarding",
            div { class: "card",
                Brand { subtitle }
                {body}
            }
        }
    }
}

/// "Use another device" and "Cancel", under every passkey question.
#[component]
fn OtherChoices(rid: String) -> Element {
    let rid2 = rid.clone();
    rsx! {
        button { class: "btn block", style: "margin-top:8px",
            onclick: move |_| answer(rid.clone(), PasskeyAnswer::Fallback),
            Icon { name: "smartphone", size: 16 }
            {t("passkey.other_device")}
        }
        button { class: "btn ghost block", style: "margin-top:8px",
            onclick: move |_| answer(rid2.clone(), PasskeyAnswer::Error("NotAllowedError")),
            {t("common.cancel")}
        }
    }
}

/// Where a new passkey for `rp` can go: logins for the website at `url` in
/// writable vaults, and those vaults (for a new login). Also whether the
/// account has one of the passkeys `excluded` names already.
fn save_targets(url: &str, rp: &str, excluded: impl Fn(&Passkey) -> bool) -> SaveTargets {
    let session = SESSION.read();
    let Some(s) = session.as_ref() else { return SaveTargets::default() };
    let writable: Vec<_> = s.vaults().into_iter().filter(|v| v.role.can_write()).collect();
    let logins = s
        .items_for_url(url)
        .into_iter()
        .filter(|i| writable.iter().any(|v| v.id == i.vault_id))
        .map(|i| (i.id.clone(), if i.subtitle.is_empty() { i.title } else { format!("{} · {}", i.title, i.subtitle) }))
        .collect();
    let exists = s.passkeys_for(rp).iter().any(|(_, p)| excluded(p));
    let vaults = writable.into_iter().map(|v| (v.id, v.name)).collect();
    SaveTargets { logins, vaults, exists }
}

#[derive(Default)]
struct SaveTargets {
    logins: Vec<(String, String)>,
    vaults: Vec<(String, String)>,
    exists: bool,
}

/// "Save passkey?": in which login or vault, and the save button. Saving
/// calls `on_save` with the login's id ("" for a new login) and the vault.
#[component]
fn SaveForm(
    rp: String,
    who: String,
    logins: Vec<(String, String)>,
    vaults: Vec<(String, String)>,
    #[props(default)] busy: bool,
    on_save: EventHandler<(String, String)>,
    children: Element,
) -> Element {
    let default_vault = SESSION.peek().as_ref().and_then(|s| s.default_vault_id()).unwrap_or_default();
    let first = logins.first().map(|(id, _)| id.clone()).unwrap_or_default();
    let mut target = use_signal(move || first);
    let mut vault = use_signal(move || default_vault);
    rsx! {
        h2 { {t("passkey.save_title")} }
        p { class: "lead", {t("passkey.save_lead").replace("{site}", &rp).replace("{user}", &who)} }
        div { class: "form-group",
            label { class: "label", {t("passkey.save_in")} }
            select { class: "input", onchange: move |e| target.set(e.value()),
                for (id , label) in logins.iter() {
                    option { key: "{id}", value: "{id}", selected: target() == *id, "{label}" }
                }
                option { value: "", selected: target().is_empty(), {t("passkey.new_login")} }
            }
        }
        if target().is_empty() && vaults.len() > 1 {
            div { class: "form-group",
                label { class: "label", {t("vault.vault")} }
                select { class: "input", onchange: move |e| vault.set(e.value()),
                    for (id , name) in vaults.iter() {
                        option { key: "{id}", value: "{id}", selected: vault() == *id, "{name}" }
                    }
                }
            }
        }
        button { class: "btn primary block", disabled: busy,
            onclick: move |_| on_save.call((target(), vault())),
            Icon { name: "key", size: 16 }
            {t("passkey.save")}
        }
        {children}
    }
}

#[component]
fn CreatePasskey(request: PasskeyRequest) -> Element {
    let options: Option<CreationOptions> = serde_json::from_value(request.options.clone()).ok();
    let rp_id = options.as_ref().map(|o| passkey::rp_id_for(&request.origin, o.rp_id.as_deref()));
    let rid = request.rid.clone();
    let (Some(options), Some(Ok(rp))) = (options, rp_id) else {
        return rsx! {
            div { class: "error-box", {t("passkey.not_allowed")} }
            OtherChoices { rid }
        };
    };
    let excluded = options.exclude_credentials.clone();
    let targets = save_targets(&request.origin, &rp, |p| excluded.iter().any(|e| e == &p.credential_id));
    if targets.exists {
        return rsx! {
            h2 { {t("passkey.save_title")} }
            div { class: "info-box small", {t("passkey.exists")} }
            button { class: "btn primary block",
                onclick: move |_| answer(rid.clone(), PasskeyAnswer::Error("InvalidStateError")),
                {t("common.close")}
            }
        };
    }
    let who = if options.user_name.is_empty() { options.user_display_name.clone() } else { options.user_name.clone() };
    let origin = request.origin.clone();
    let rid_save = rid.clone();
    let save = move |(item, vault_id): (String, String)| {
        let created = passkey::create(&origin, &options);
        let (passkey, registration) = match created {
            Ok(r) => r,
            Err(e) => {
                toast_err(&core_error(&e));
                return;
            }
        };
        let item = (!item.is_empty()).then_some(item);
        let url = origin.clone();
        let saved = mutate(move |s| s.save_passkey(&vault_id, item.as_deref(), &url, passkey));
        if saved.is_some() {
            let json = serde_json::to_value(&registration).unwrap_or_default();
            answer(rid_save.clone(), PasskeyAnswer::Result(json));
        }
    };
    rsx! {
        SaveForm { rp, who, logins: targets.logins, vaults: targets.vaults, on_save: save,
            OtherChoices { rid }
        }
    }
}

#[component]
fn UsePasskey(request: PasskeyRequest) -> Element {
    let options: Option<RequestOptions> = serde_json::from_value(request.options.clone()).ok();
    let rp_id = options.as_ref().map(|o| passkey::rp_id_for(&request.origin, o.rp_id.as_deref()));
    let rid = request.rid.clone();
    let (Some(options), Some(Ok(rp))) = (options, rp_id) else {
        return rsx! {
            div { class: "error-box", {t("passkey.not_allowed")} }
            OtherChoices { rid }
        };
    };
    let choices = passkey_choices(&rp, |p| {
        options.allow_credentials.is_empty()
            || options.allow_credentials.iter().any(|c| c.trim_end_matches('=') == p.credential_id)
    });

    rsx! {
        h2 { {t("passkey.use_title")} }
        p { class: "lead", {t("passkey.use_lead").replace("{site}", &rp)} }
        if choices.is_empty() {
            div { class: "info-box small", {t("passkey.none").replace("{site}", &rp)} }
        }
        for (title , p) in choices {
            button { class: "choice", key: "{p.credential_id}",
                onclick: {
                    let (origin, options, rid, p) = (request.origin.clone(), options.clone(), rid.clone(), p.clone());
                    move |_| match passkey::assert(&p, &origin, &options) {
                        Ok(assertion) => {
                            let json = serde_json::to_value(&assertion).unwrap_or_default();
                            answer(rid.clone(), PasskeyAnswer::Result(json));
                        }
                        Err(e) => toast_err(&core_error(&e)),
                    }
                },
                PasskeyChoice { title, passkey: p.clone() }
            }
        }
        OtherChoices { rid }
    }
}

/// The passkeys for `rp` that `allowed` accepts, with the title of their item.
fn passkey_choices(rp: &str, allowed: impl Fn(&Passkey) -> bool) -> Vec<(String, Passkey)> {
    SESSION
        .read()
        .as_ref()
        .map(|s| {
            s.passkeys_for(rp)
                .into_iter()
                .filter(|(_, p)| allowed(p))
                .map(|(item_id, p)| (s.item(&item_id).map(|i| i.title.clone()).unwrap_or_default(), p))
                .collect()
        })
        .unwrap_or_default()
}

#[component]
fn PasskeyChoice(title: String, passkey: Passkey) -> Element {
    rsx! {
        Icon { name: "key", size: 22 }
        div {
            div { class: "t", if passkey.user_name.is_empty() { "{passkey.user_display_name}" } else { "{passkey.user_name}" } }
            div { class: "d", "{title}" }
        }
    }
}

/// Windows Hello before answering, when 2Secret was unlocked already.
/// False when the person cancelled or it failed (and said so).
async fn verified(rid: &str, verify: bool, user_name: &str, hint: String) -> bool {
    if !verify {
        return true;
    }
    match windows_passkeys::verify_user(rid, user_name, &hint).await {
        Ok(()) => true,
        Err(Unverified::Cancelled) => false,
        Err(Unverified::Failed(e)) => {
            toast_err(&t("winpasskeys.verify_failed").replace("{error}", &e));
            false
        }
    }
}

/// Cancel, under the questions for Windows: Windows offers its other
/// choices (phone, security key) itself.
#[component]
fn CancelForWindows(rid: String) -> Element {
    rsx! {
        button { class: "btn ghost block", style: "margin-top:8px",
            onclick: move |_| answer_windows(&rid, Outcome::Refused(Refusal::Cancelled)),
            {t("common.cancel")}
        }
    }
}

#[component]
fn CreateForWindows(rid: String, creation: SystemCreation, verify: bool) -> Element {
    let mut busy = use_signal(|| false);
    let rp = creation.rp_id.clone();
    if !creation.algorithms.is_empty() && !creation.algorithms.contains(&ES256) {
        return rsx! {
            div { class: "error-box", {t("winpasskeys.unsupported_key")} }
            button { class: "btn primary block",
                onclick: move |_| answer_windows(&rid, Outcome::Refused(Refusal::NotSupported)),
                {t("common.close")}
            }
        };
    }
    let targets = save_targets(&format!("https://{rp}"), &rp, |p| creation.excludes(p));
    if targets.exists {
        return rsx! {
            h2 { {t("passkey.save_title")} }
            div { class: "info-box small", {t("passkey.exists")} }
            button { class: "btn primary block",
                onclick: move |_| answer_windows(&rid, Outcome::Refused(Refusal::Exists)),
                {t("common.close")}
            }
        };
    }
    let who =
        if creation.user_name.is_empty() { creation.user_display_name.clone() } else { creation.user_name.clone() };
    let rid_save = rid.clone();
    let who_save = who.clone();
    let save = move |(item, vault_id): (String, String)| {
        let (rid, creation, who) = (rid_save.clone(), creation.clone(), who_save.clone());
        spawn(async move {
            busy.set(true);
            let hint = t("winpasskeys.verify_save").replace("{site}", &creation.rp_id);
            let ok = verified(&rid, verify, &who, hint).await;
            busy.set(false);
            if !ok {
                return;
            }
            let (passkey, auth_data) = match passkey::create_for_system(&creation) {
                Ok(created) => created,
                Err(e) => {
                    toast_err(&core_error(&e));
                    return;
                }
            };
            let item = (!item.is_empty()).then_some(item);
            let url = format!("https://{}", creation.rp_id);
            // Saved before Windows hears of it: the website keeps the
            // public key either way.
            if mutate(move |s| s.save_passkey(&vault_id, item.as_deref(), &url, passkey)).is_some() {
                answer_windows(&rid, Outcome::Created(auth_data));
            }
        });
    };
    rsx! {
        SaveForm { rp, who, logins: targets.logins, vaults: targets.vaults, busy: busy(), on_save: save,
            CancelForWindows { rid }
        }
    }
}

#[component]
fn UseForWindows(rid: String, sign_in: SystemSignIn, verify: bool) -> Element {
    let mut busy = use_signal(|| false);
    let rp = sign_in.rp_id.clone();
    let choices = passkey_choices(&rp, |p| sign_in.allows(p));
    let any = !choices.is_empty();
    let rid_none = rid.clone();
    rsx! {
        h2 { {t("passkey.use_title")} }
        p { class: "lead", {t("passkey.use_lead").replace("{site}", &rp)} }
        if choices.is_empty() {
            div { class: "info-box small", {t("passkey.none").replace("{site}", &rp)} }
            button { class: "btn primary block",
                onclick: move |_| answer_windows(&rid_none, Outcome::Refused(Refusal::NotFound)),
                {t("common.close")}
            }
        }
        for (title , p) in choices {
            button { class: "choice", key: "{p.credential_id}", disabled: busy(),
                onclick: {
                    let (rid, sign_in, p) = (rid.clone(), sign_in.clone(), p.clone());
                    move |_| {
                        let (rid, sign_in, p) = (rid.clone(), sign_in.clone(), p.clone());
                        spawn(async move {
                            busy.set(true);
                            let who = if p.user_name.is_empty() { p.user_display_name.clone() } else { p.user_name.clone() };
                            let hint = t("winpasskeys.verify_sign_in").replace("{site}", &p.rp_id);
                            let ok = verified(&rid, verify, &who, hint).await;
                            busy.set(false);
                            if !ok {
                                return;
                            }
                            match passkey::sign_for_system(&p, &sign_in) {
                                Ok(assertion) => answer_windows(&rid, Outcome::Signed(assertion)),
                                Err(e) => toast_err(&core_error(&e)),
                            }
                        });
                    }
                },
                PasskeyChoice { title, passkey: p.clone() }
            }
        }
        if any {
            CancelForWindows { rid: rid.clone() }
        }
    }
}
