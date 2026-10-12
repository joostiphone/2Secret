//! Modal dialogs.

use dioxus::prelude::*;
use twosecret_core::api::MemberDto;
use twosecret_core::item::{Category, Item};
use twosecret_core::profile::Role;

use crate::components::widgets::*;
use crate::i18n::{category_name, role_name, t};
use crate::icons::{category_icon, either, Icon};
use crate::state::*;

fn close() {
    *MODAL.write() = None;
}

#[component]
pub fn ModalHost() -> Element {
    let modal = MODAL.read().clone();
    match modal {
        None => rsx! {},
        Some(Modal::NewItem) => rsx! { NewItemModal {} },
        Some(Modal::NewVault) => rsx! { VaultFormModal { id: None } },
        Some(Modal::EditVault(id)) => rsx! { VaultFormModal { id: Some(id) } },
        Some(Modal::ShareVault(id)) => rsx! { ShareModal { id } },
        Some(Modal::DeleteVault(id)) => rsx! { DeleteVaultModal { id } },
        Some(Modal::MoveItem(id)) => rsx! { MoveItemModal { id } },
        Some(Modal::DeleteItem(id)) => rsx! { DeleteItemModal { id } },
        Some(Modal::Reauth) => rsx! { ReauthModal {} },
        Some(Modal::ForgetDevice) => rsx! { ForgetModal {} },
    }
}

#[component]
fn NewItemModal() -> Element {
    let start = move |c: Category| {
        let vault = {
            let session = SESSION.peek();
            let Some(s) = session.as_ref() else { return };
            match &*NAV.peek() {
                Nav::Vault(id) if s.vault(id).is_some_and(|v| v.role.can_write()) => Some(id.clone()),
                _ => s.default_vault_id(),
            }
        };
        let Some(vault_id) = vault else {
            toast_err(t("err.no_vault"));
            return;
        };
        let mut item = Item::new(c, "");
        if let Nav::Tag(tag) = &*NAV.peek() {
            item.tags.push(tag.clone());
        }
        if *NAV.peek() == Nav::Favorites {
            item.favorite = true;
        }
        if c.has_urls() {
            item.urls.push(String::new());
        }
        *EDITING.write() = Some(Draft { item, vault_id, is_new: true });
        *SELECTED.write() = None;
        *PANE.write() = Pane::Detail;
        if NAV.peek().is_page() || matches!(*NAV.peek(), Nav::Trash) {
            *NAV.write() = Nav::All;
        }
        close();
    };
    rsx! {
        ModalFrame { title: t("item.new"),
            div { class: "menu-grid",
                for c in Category::ALL {
                    button { key: "{c.id()}", onclick: move |_| start(c),
                        Icon { name: category_icon(c), size: 18 }
                        span { {category_name(c)} }
                    }
                }
            }
        }
    }
}

#[component]
fn VaultFormModal(id: Option<String>) -> Element {
    let existing = id.as_ref().and_then(|id| SESSION.peek().as_ref().and_then(|s| s.vault(id)));
    let mut name = use_signal(|| existing.as_ref().map(|v| v.name.clone()).unwrap_or_default());
    let mut description = use_signal(|| existing.as_ref().map(|v| v.description.clone()).unwrap_or_default());
    let title = if id.is_some() { t("vault.edit") } else { t("vault.new") };
    let id2 = id.clone();
    let save = move |_| {
        let (n, d) = (name(), description());
        if n.trim().is_empty() {
            return;
        }
        match &id2 {
            Some(id) => {
                let id = id.clone();
                if mutate(|s| s.update_vault(&id, &n, &d, None)).is_some() {
                    close();
                }
            }
            None => {
                if let Some(new_id) = mutate(|s| s.create_vault(&n, &d)) {
                    *NAV.write() = Nav::Vault(new_id);
                    *SELECTED.write() = None;
                    *PANE.write() = Pane::List;
                    close();
                }
            }
        }
    };
    rsx! {
        ModalFrame { title,
            footer: rsx! {
                button { class: "btn", onclick: move |_| close(), {t("common.cancel")} }
                button { class: "btn primary", onclick: save, {t("common.save")} }
            },
            div { class: "form-group",
                label { class: "label", {t("vault.name")} }
                input { class: "input", initial_value: "{name}", autofocus: true, onmounted: focus_on_mount, oninput: move |e| name.set(e.value()) }
            }
            div { class: "form-group",
                label { class: "label", {t("vault.description")} }
                input { class: "input", initial_value: "{description}", placeholder: t("common.optional"), oninput: move |e| description.set(e.value()) }
            }
        }
    }
}

#[component]
fn DeleteVaultModal(id: String) -> Element {
    let Some(v) = SESSION.peek().as_ref().and_then(|s| s.vault(&id)) else { return rsx! {} };
    let owner = v.is_owner;
    let id2 = id.clone();
    rsx! {
        ModalFrame { title: if owner { t("vault.delete") } else { t("vault.leave") },
            footer: rsx! {
                button { class: "btn", onclick: move |_| close(), {t("common.cancel")} }
                button { class: "btn danger",
                    onclick: move |_| {
                        if mutate(|s| s.delete_vault(&id2)).is_some() {
                            *NAV.write() = Nav::All;
                            *SELECTED.write() = None;
                            close();
                        }
                    },
                    if owner { {t("vault.delete")} } else { {t("vault.leave")} }
                }
            },
            p { strong { "{v.name}" } " · {v.item_count} {t(\"vault.items\")}" }
            p { class: "muted", if owner { {t("vault.delete_warning")} } else { {t("vault.leave_warning")} } }
        }
    }
}

#[component]
fn MoveItemModal(id: String) -> Element {
    let session = SESSION.peek();
    let current = session.as_ref().and_then(|s| s.item_vault(&id)).unwrap_or_default().to_string();
    let vaults: Vec<_> = session
        .as_ref()
        .map(|s| s.vaults().into_iter().filter(|v| v.role.can_write() && v.id != current).collect())
        .unwrap_or_default();
    drop(session);
    rsx! {
        ModalFrame { title: t("item.move"),
            if vaults.is_empty() {
                p { class: "muted", {t("item.move_none")} }
            }
            for v in vaults {
                button { class: "choice", key: "{v.id}",
                    onclick: {
                        let id = id.clone();
                        move |_| {
                            if let Some(new_id) = mutate(|s| s.move_item(&id, &v.id)) {
                                *SELECTED.write() = Some(new_id);
                                toast(t("toast.moved"));
                                close();
                            }
                        }
                    },
                    Icon { name: either(v.is_shared(), "users", "vault"), size: 20 }
                    div { div { class: "t", "{v.name}" } div { class: "d", "{v.item_count} {t(\"vault.items\")}" } }
                }
            }
        }
    }
}

#[component]
fn DeleteItemModal(id: String) -> Element {
    let title = SESSION.peek().as_ref().and_then(|s| s.item(&id).map(|i| i.title.clone())).unwrap_or_default();
    rsx! {
        ModalFrame { title: t("item.delete_forever"),
            footer: rsx! {
                button { class: "btn", onclick: move |_| close(), {t("common.cancel")} }
                button { class: "btn danger",
                    onclick: move |_| {
                        if mutate(|s| s.delete_item(&id)).is_some() {
                            *SELECTED.write() = None;
                            *PANE.write() = Pane::List;
                            close();
                        }
                    },
                    {t("common.delete")}
                }
            },
            p { strong { "{title}" } }
            p { class: "muted", {t("item.delete_warning")} }
        }
    }
}

#[component]
fn ShareModal(id: String) -> Element {
    let mut members = use_signal(|| None::<Vec<MemberDto>>);
    let mut email = use_signal(String::new);
    let mut email_rev = use_signal(|| 0u32);
    let mut role = use_signal(|| Role::Editor);
    let mut error = use_signal(|| None::<String>);
    let vault = SESSION.peek().as_ref().and_then(|s| s.vault(&id));
    let linked = SESSION.peek().as_ref().is_some_and(|s| s.server().is_some());
    let my_id = SESSION.peek().as_ref().map(|s| s.account().id.clone()).unwrap_or_default();
    let vid = id.clone();
    let load = move || {
        let vid = vid.clone();
        spawn(async move {
            let client = SESSION.peek().as_ref().and_then(|s| twosecret_client::client_for(s).ok());
            let Some(client) = client else { return };
            match client.members(&vid).await {
                Ok(list) => members.set(Some(list)),
                Err(e) => error.set(Some(client_error(&e))),
            }
        });
    };
    let load2 = load.clone();
    use_hook(move || {
        if linked {
            load2();
        }
    });
    let Some(vault) = vault else { return rsx! {} };
    if !linked {
        return rsx! {
            ModalFrame { title: t("vault.share"),
                p { {t("share.needs_server")} }
                button { class: "btn primary", onclick: move |_| { close(); *NAV.write() = Nav::Settings; }, {t("settings.connect")} }
            }
        };
    }
    let vid_share = id.clone();
    let load_after_share = load.clone();
    let share = move |_| {
        let mail = email();
        if !mail.contains('@') {
            error.set(Some(t("create.err_email").into()));
            return;
        }
        let Some(mut session) = session_copy() else { return };
        let r = role();
        let vid = vid_share.clone();
        let reload = load_after_share.clone();
        error.set(None);
        spawn(async move {
            busy(t("busy.sharing"));
            let result = twosecret_client::share_vault(&mut session, &vid, &mail, r).await;
            unbusy();
            match result {
                Ok(user) => {
                    install_session(session);
                    email.set(String::new());
                    email_rev += 1;
                    let fp = twosecret_core::crypto::AccountPublicKeys::from_b64(
                        &user.public_key,
                        user.pq_public_key.as_deref(),
                    )
                    .map(|k| k.fingerprint())
                    .unwrap_or_default();
                    toast(&format!("{} {} ({fp})", t("share.shared_with"), user.name));
                    reload();
                }
                Err(e) => error.set(Some(client_error(&e))),
            }
        });
    };

    rsx! {
        ModalFrame { title: format!("{} · {}", t("vault.share"), vault.name),
            if let Some(err) = error() { div { class: "error-box", "{err}" } }
            p { class: "small muted", {t("share.explain")} }
            div { class: "row", style: "margin-bottom:16px",
                for k in [email_rev()] {
                    input { key: "{k}", class: "input grow", r#type: "email", placeholder: t("common.email"), initial_value: "{email}", autocapitalize: "off",
                        oninput: move |e| email.set(e.value()) }
                }
                select { class: "input", style: "width:auto",
                    onchange: move |e| { if let Some(r) = Role::parse(&e.value()) { role.set(r); } },
                    for r in [Role::Viewer, Role::Editor, Role::Manager] {
                        option { key: "{r.id()}", value: "{r.id()}", selected: role() == r, {role_name(r)} }
                    }
                }
                button { class: "btn primary", onclick: share, {t("vault.share")} }
            }
            div { class: "section", style: "margin-bottom:0",
                match members() {
                    None => rsx! { div { class: "section-body row", style: "padding-top:14px", div { class: "spinner" } } },
                    Some(list) => rsx! {
                        for m in list {
                            MemberRow { key: "{m.account_id}", vault_id: id.clone(), member: m.clone(), me: my_id.clone(), can_manage: vault.role.can_manage(),
                                changed: { let load = load.clone(); move |_| load() } }
                        }
                    },
                }
            }
        }
    }
}

#[component]
fn MemberRow(vault_id: String, member: MemberDto, me: String, can_manage: bool, changed: EventHandler<()>) -> Element {
    let fingerprint =
        twosecret_core::crypto::AccountPublicKeys::from_b64(&member.public_key, member.pq_public_key.as_deref())
            .map(|k| k.fingerprint())
            .unwrap_or_default();
    let editable = can_manage && member.role != Role::Owner && member.account_id != me;
    let vid = vault_id.clone();
    let aid = member.account_id.clone();
    let set_role = move |r: Role| {
        let Some(mut session) = session_copy() else { return };
        let (vid, aid) = (vid.clone(), aid.clone());
        spawn(async move {
            busy(t("busy.working"));
            let res = twosecret_client::set_member_role(&mut session, &vid, &aid, r).await;
            unbusy();
            match res {
                Ok(()) => {
                    install_session(session);
                    changed.call(());
                }
                Err(e) => toast_err(&client_error(&e)),
            }
        });
    };
    let (vid2, aid2) = (vault_id.clone(), member.account_id.clone());
    let remove = move |_| {
        let Some(mut session) = session_copy() else { return };
        let (vid, aid) = (vid2.clone(), aid2.clone());
        spawn(async move {
            busy(t("busy.working"));
            let res = twosecret_client::remove_member(&mut session, &vid, &aid).await;
            unbusy();
            match res {
                Ok(()) => {
                    install_session(session);
                    toast(t("share.removed"));
                    changed.call(());
                }
                Err(e) => toast_err(&client_error(&e)),
            }
        });
    };
    rsx! {
        div { class: "settings-row",
            div { class: "k",
                div { class: "t", "{member.name}" }
                div { class: "d", "{member.email} · " span { class: "mono", "{fingerprint}" } }
            }
            if editable {
                select { class: "input", style: "min-width:0",
                    onchange: move |e| { if let Some(r) = Role::parse(&e.value()) { set_role(r); } },
                    for r in [Role::Viewer, Role::Editor, Role::Manager] {
                        option { key: "{r.id()}", value: "{r.id()}", selected: member.role == r, {role_name(r)} }
                    }
                }
                button { class: "icon-btn", title: t("common.remove"), onclick: remove, Icon { name: "x", size: 16 } }
            } else {
                span { class: "muted small", {role_name(member.role)} }
            }
        }
    }
}

#[component]
fn ReauthModal() -> Element {
    let mut password = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let submit = move || {
        let pw = password();
        let Some(profile) = SESSION.peek().as_ref().map(|s| s.profile().clone()) else { return };
        spawn(async move {
            busy(t("busy.signing_in"));
            let result = unlock_online(profile, pw).await;
            unbusy();
            match result {
                Ok(session) => {
                    install_session(session);
                    SYNC.write().needs_reauth = false;
                    close();
                    dioxus::core::spawn_forever(run_sync(true));
                }
                Err(e) => error.set(Some(e)),
            }
        });
    };
    rsx! {
        ModalFrame { title: t("settings.sign_in_again"),
            footer: rsx! {
                button { class: "btn", onclick: move |_| close(), {t("common.cancel")} }
                button { class: "btn primary", onclick: move |_| submit(), {t("signin.submit")} }
            },
            p { class: "muted", {t("reauth.explain")} }
            if let Some(err) = error() { div { class: "error-box", "{err}" } }
            PasswordInput { value: password(), oninput: move |v| password.set(v), autofocus: true, placeholder: t("common.master_password"), onenter: move |_| submit() }
        }
    }
}

#[component]
fn ForgetModal() -> Element {
    let local_only = load_profile().is_some_and(|p| p.server.is_none());
    rsx! {
        ModalFrame { title: t("settings.forget"),
            footer: rsx! {
                button { class: "btn", onclick: move |_| close(), {t("common.cancel")} }
                button { class: "btn danger", onclick: move |_| { close(); forget_device(); }, {t("settings.forget_button")} }
            },
            p { {t("settings.forget_desc")} }
            if local_only {
                div { class: "error-box", {t("forget.local_warning")} }
            } else {
                div { class: "info-box small", {t("forget.server_info")} }
            }
        }
    }
}
