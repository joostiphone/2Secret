//! Browser extension: a website asked for a passkey and opened this window.

use dioxus::prelude::*;
use twosecret_core::passkey::{self, CreationOptions, Passkey, RequestOptions};

use crate::components::widgets::*;
use crate::extension::{self, PasskeyAnswer, PasskeyRequest};
use crate::i18n::t;
use crate::icons::Icon;
use crate::state::*;

/// Answer the page; the window closes itself.
fn answer(rid: String, answer: PasskeyAnswer) {
    *PASSKEY.write() = None;
    dioxus::core::spawn_forever(async move { extension::answer_passkey(&rid, answer).await });
}

#[component]
pub fn PasskeyPrompt() -> Element {
    let Some(request) = PASSKEY.read().clone() else { return rsx! {} };
    rsx! {
        div { class: "onboarding",
            div { class: "card",
                Brand { subtitle: request.origin.clone() }
                if request.kind == "create" {
                    CreatePasskey { request }
                } else {
                    UsePasskey { request }
                }
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

#[component]
fn CreatePasskey(request: PasskeyRequest) -> Element {
    let options: Option<CreationOptions> = serde_json::from_value(request.options.clone()).ok();
    let rp_id = options.as_ref().map(|o| passkey::rp_id_for(&request.origin, o.rp_id.as_deref()));

    // Where to save: an existing login for the site, or a new one.
    let (logins, vaults, exists) = {
        let session = SESSION.read();
        match (session.as_ref(), &rp_id) {
            (Some(s), Some(Ok(rp))) => {
                let writable: Vec<_> = s.vaults().into_iter().filter(|v| v.role.can_write()).collect();
                let logins: Vec<(String, String)> = s
                    .items_for_url(&request.origin)
                    .into_iter()
                    .filter(|i| writable.iter().any(|v| v.id == i.vault_id))
                    .map(|i| {
                        (
                            i.id.clone(),
                            if i.subtitle.is_empty() { i.title } else { format!("{} · {}", i.title, i.subtitle) },
                        )
                    })
                    .collect();
                let excluded = options.as_ref().map(|o| o.exclude_credentials.clone()).unwrap_or_default();
                let exists = s.passkeys_for(rp).iter().any(|(_, p)| excluded.iter().any(|e| e == &p.credential_id));
                let vaults: Vec<(String, String)> = writable.into_iter().map(|v| (v.id, v.name)).collect();
                (logins, vaults, exists)
            }
            _ => (Vec::new(), Vec::new(), false),
        }
    };
    let default_vault = SESSION.peek().as_ref().and_then(|s| s.default_vault_id()).unwrap_or_default();
    let mut target = use_signal(|| logins.first().map(|(id, _)| id.clone()).unwrap_or_default());
    let mut vault = use_signal(move || default_vault);

    let rid = request.rid.clone();
    let (Some(options), Some(Ok(rp))) = (options, rp_id) else {
        return rsx! {
            div { class: "error-box", {t("passkey.not_allowed")} }
            OtherChoices { rid }
        };
    };
    if exists {
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
    let save = move |_| {
        let (item, vault_id) = (target(), vault());
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
        button { class: "btn primary block", onclick: save,
            Icon { name: "key", size: 16 }
            {t("passkey.save")}
        }
        OtherChoices { rid }
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
    let choices: Vec<(String, Passkey)> = SESSION
        .read()
        .as_ref()
        .map(|s| {
            s.passkeys_for(&rp)
                .into_iter()
                .filter(|(_, p)| {
                    options.allow_credentials.is_empty()
                        || options.allow_credentials.iter().any(|c| c.trim_end_matches('=') == p.credential_id)
                })
                .map(|(item_id, p)| (s.item(&item_id).map(|i| i.title.clone()).unwrap_or_default(), p))
                .collect()
        })
        .unwrap_or_default();

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
                Icon { name: "key", size: 22 }
                div {
                    div { class: "t", if p.user_name.is_empty() { "{p.user_display_name}" } else { "{p.user_name}" } }
                    div { class: "d", "{title}" }
                }
            }
        }
        OtherChoices { rid }
    }
}
