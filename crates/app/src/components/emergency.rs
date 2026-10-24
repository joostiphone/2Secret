//! Emergency access: trust someone with the vaults you own, for when you
//! cannot give them access yourself (`twosecret_client::add_emergency_contact`
//! and the server's `emergency` module). The settings section, and the
//! banner when someone asks for access or was given it.

use dioxus::prelude::*;
use twosecret_core::api::EmergencyContactDto;
use twosecret_core::crypto::AccountPublicKeys;

use crate::i18n::t;
use crate::icons::Icon;
use crate::platform;
use crate::state::*;

/// Waiting periods to choose from (days).
const WAIT_DAYS: [u32; 5] = [1, 2, 7, 14, 30];

#[derive(Clone, Copy, PartialEq)]
enum Action {
    Request,
    Approve,
    Reject,
    Open,
    Remove,
}

impl Action {
    fn done(self) -> &'static str {
        match self {
            Action::Request => t("emergency.requested"),
            Action::Approve => t("emergency.approved"),
            Action::Reject => t("emergency.rejected"),
            Action::Open => t("emergency.opened"),
            Action::Remove => t("emergency.removed"),
        }
    }
}

/// Load what the server says now.
fn refresh() {
    let Some(session) = session_copy() else { return };
    spawn(async move {
        if let Ok(overview) = twosecret_client::emergency_overview(&session).await {
            *EMERGENCY.write() = Some(overview);
        }
    });
}

fn perform(action: Action, id: String) {
    let Some(mut session) = session_copy() else { return };
    spawn(async move {
        busy(t("busy.working"));
        let result = match action {
            Action::Request => twosecret_client::request_emergency_access(&session, &id).await,
            Action::Approve => twosecret_client::approve_emergency_access(&session, &id).await,
            Action::Reject => twosecret_client::reject_emergency_access(&mut session, &id).await,
            Action::Open => twosecret_client::open_emergency_access(&mut session, &id).await,
            Action::Remove => twosecret_client::remove_emergency_contact(&mut session, &id).await,
        };
        let overview = twosecret_client::emergency_overview(&session).await;
        unbusy();
        match result {
            Ok(()) => {
                install_session(session);
                if let Ok(overview) = overview {
                    *EMERGENCY.write() = Some(overview);
                }
                toast(action.done());
            }
            Err(e) => report_error(&e, |m| toast_err(&m)),
        }
    });
}

fn wait_label(days: u32) -> String {
    if days == 1 {
        t("emergency.day").to_string()
    } else {
        t("emergency.days").replace("{n}", &days.to_string())
    }
}

/// What a contact may do, from the side of whoever trusts them.
fn contact_status(c: &EmergencyContactDto) -> String {
    let date = |ts: Option<i64>| platform::local_time(ts.unwrap_or_default());
    match (c.requested_at, c.granted) {
        (None, _) => t("emergency.ready").replace("{wait}", &wait_label(c.wait_days)),
        (Some(_), false) => {
            t("emergency.asked").replace("{date}", &date(c.requested_at)).replace("{until}", &date(c.grants_at))
        }
        (Some(_), true) if c.opened => t("emergency.has_opened").replace("{date}", &date(c.grants_at)),
        (Some(_), true) => t("emergency.has_access").replace("{date}", &date(c.grants_at)),
    }
}

/// The same, from the contact's side.
fn trusted_status(c: &EmergencyContactDto) -> String {
    let date = |ts: Option<i64>| platform::local_time(ts.unwrap_or_default());
    match (c.requested_at, c.granted) {
        (None, _) => t("emergency.can_ask").replace("{wait}", &wait_label(c.wait_days)),
        (Some(_), false) => {
            t("emergency.you_asked").replace("{date}", &date(c.requested_at)).replace("{until}", &date(c.grants_at))
        }
        (Some(_), true) if c.opened => t("emergency.you_opened").to_string(),
        (Some(_), true) => t("emergency.you_have_access").replace("{date}", &date(c.grants_at)),
    }
}

/// Settings → Emergency access.
#[component]
pub fn EmergencySection() -> Element {
    let mut adding = use_signal(|| false);
    let linked = SESSION.read().as_ref().is_some_and(|s| s.server().is_some() && s.server_token().is_some());
    use_hook(move || {
        if linked {
            refresh();
        }
    });
    let overview = EMERGENCY.read().clone();
    rsx! {
        div { class: "section",
            div { class: "section-title", {t("emergency.title")} }
            if !linked {
                div { class: "settings-row",
                    div { class: "k", div { class: "d", {t("emergency.needs_server")} } }
                }
            } else {
                div { class: "settings-row",
                    div { class: "k",
                        div { class: "t", {t("emergency.contacts")} }
                        div { class: "d", {t("emergency.contacts_desc")} }
                    }
                    button { class: "btn small", onclick: move |_| adding.toggle(), Icon { name: "plus", size: 14 } {t("emergency.add")} }
                }
                if adding() {
                    AddContactForm { done: move |_| adding.set(false) }
                }
                if let Some(overview) = overview {
                    for c in overview.contacts {
                        div { class: "settings-row", key: "{c.id}",
                            Icon { name: "user", size: 16 }
                            div { class: "k",
                                div { class: "t", "{c.name} ({c.email})" }
                                div { class: "d", {contact_status(&c)} }
                            }
                            if c.requested_at.is_some() && !c.granted {
                                button { class: "btn small primary", onclick: { let id = c.id.clone(); move |_| perform(Action::Approve, id.clone()) }, {t("emergency.approve")} }
                            }
                            if c.requested_at.is_some() {
                                button { class: "btn small danger", onclick: { let id = c.id.clone(); move |_| perform(Action::Reject, id.clone()) },
                                    if c.granted { {t("emergency.end")} } else { {t("emergency.deny")} }
                                }
                            }
                            button { class: "icon-btn", title: t("emergency.remove"), onclick: { let id = c.id.clone(); move |_| perform(Action::Remove, id.clone()) },
                                Icon { name: "trash", size: 16 }
                            }
                        }
                    }
                    if !overview.trusted_by.is_empty() {
                        div { class: "settings-row",
                            div { class: "k",
                                div { class: "t", {t("emergency.trusted_by")} }
                                div { class: "d", {t("emergency.trusted_by_desc")} }
                            }
                        }
                    }
                    for c in overview.trusted_by {
                        div { class: "settings-row", key: "{c.id}",
                            Icon { name: "users", size: 16 }
                            div { class: "k",
                                div { class: "t", "{c.name} ({c.email})" }
                                div { class: "d", {trusted_status(&c)} }
                            }
                            if c.requested_at.is_none() {
                                button { class: "btn small", onclick: { let id = c.id.clone(); move |_| perform(Action::Request, id.clone()) }, {t("emergency.request")} }
                            } else if !c.granted {
                                button { class: "btn small", onclick: { let id = c.id.clone(); move |_| perform(Action::Reject, id.clone()) }, {t("emergency.withdraw")} }
                            } else if !c.opened {
                                button { class: "btn small primary", onclick: { let id = c.id.clone(); move |_| perform(Action::Open, id.clone()) }, {t("emergency.open")} }
                            }
                            button { class: "icon-btn", title: t("emergency.leave"), onclick: { let id = c.id.clone(); move |_| perform(Action::Remove, id.clone()) },
                                Icon { name: "trash", size: 16 }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn AddContactForm(done: EventHandler<()>) -> Element {
    let mut email = use_signal(String::new);
    let mut wait = use_signal(|| 7u32);
    let mut error = use_signal(|| None::<String>);
    let add = move |_| {
        let mail = email().trim().to_string();
        if !mail.contains('@') {
            error.set(Some(t("create.err_email").into()));
            return;
        }
        let Some(mut session) = session_copy() else { return };
        let days = wait();
        error.set(None);
        spawn(async move {
            busy(t("busy.working"));
            let result = twosecret_client::add_emergency_contact(&mut session, &mail, days).await;
            let overview = twosecret_client::emergency_overview(&session).await;
            unbusy();
            match result {
                Ok(user) => {
                    install_session(session);
                    if let Ok(overview) = overview {
                        *EMERGENCY.write() = Some(overview);
                    }
                    let fp = AccountPublicKeys::from_b64(&user.public_key, user.pq_public_key.as_deref())
                        .map(|k| k.fingerprint())
                        .unwrap_or_default();
                    toast(&t("emergency.added").replace("{name}", &user.name).replace("{fp}", &fp));
                    done.call(());
                }
                Err(e) => report_error(&e, |m| error.set(Some(m))),
            }
        });
    };
    rsx! {
        div { class: "section-body", style: "padding-top:12px;border-bottom:1px solid var(--border)",
            if let Some(err) = error() { div { class: "error-box", "{err}" } }
            p { class: "small muted", {t("emergency.add_desc")} }
            div { class: "row", style: "gap:8px;flex-wrap:wrap;margin-bottom:12px",
                input { class: "input grow", r#type: "email", placeholder: t("common.email"), autocapitalize: "off",
                    oninput: move |e| email.set(e.value()),
                }
                select { class: "input", style: "width:auto",
                    onchange: move |e| if let Ok(v) = e.value().parse() { wait.set(v) },
                    for days in WAIT_DAYS {
                        option { value: "{days}", selected: wait() == days, {wait_label(days)} }
                    }
                }
                button { class: "btn primary", onclick: add, {t("emergency.add")} }
            }
        }
    }
}

/// Emergency contacts for whom the server reports other public keys than
/// this device knew: they get no vault keys until the new keys are trusted.
#[component]
pub fn KeyChangeBanner() -> Element {
    let changes = KEY_WARNINGS.read().clone();
    rsx! {
        for c in changes {
            div { class: "banner", key: "keys-{c.account_id}",
                Icon { name: "alert", size: 18 }
                div { class: "grow",
                    div { class: "t", {t("keys.banner").replace("{email}", &c.email)} }
                    div { class: "d", {t("keys.banner_desc")} }
                }
                button { class: "btn small", onclick: { let c = c.clone(); move |_| *MODAL.write() = Some(Modal::KeysChanged(c.clone())) },
                    {t("keys.view")}
                }
            }
        }
    }
}

/// Someone asks for access to your vaults, or gave you access.
#[component]
pub fn EmergencyBanner() -> Element {
    let Some(overview) = EMERGENCY.read().clone() else { return rsx! {} };
    let asking: Vec<_> = overview.contacts.into_iter().filter(|c| c.requested_at.is_some() && !c.granted).collect();
    let given: Vec<_> = overview.trusted_by.into_iter().filter(|c| c.granted && !c.opened).collect();
    rsx! {
        for c in asking {
            div { class: "banner", key: "ask-{c.id}",
                Icon { name: "alert", size: 18 }
                div { class: "grow",
                    div { class: "t", {t("emergency.banner_ask").replace("{name}", &c.name)} }
                    div { class: "d", {t("emergency.banner_ask_desc").replace("{date}", &platform::local_time(c.grants_at.unwrap_or_default()))} }
                }
                div { class: "row",
                    button { class: "btn small danger", onclick: { let id = c.id.clone(); move |_| perform(Action::Reject, id.clone()) }, {t("emergency.deny")} }
                    button { class: "btn small", onclick: { let id = c.id.clone(); move |_| perform(Action::Approve, id.clone()) }, {t("emergency.approve")} }
                }
            }
        }
        for c in given {
            div { class: "banner", key: "given-{c.id}",
                Icon { name: "users", size: 18 }
                div { class: "grow",
                    div { class: "t", {t("emergency.banner_given").replace("{name}", &c.name)} }
                    div { class: "d", {t("emergency.banner_given_desc")} }
                }
                button { class: "btn small primary", onclick: { let id = c.id.clone(); move |_| perform(Action::Open, id.clone()) }, {t("emergency.open")} }
            }
        }
    }
}
