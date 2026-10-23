//! Modal dialogs.

use dioxus::prelude::*;
use twosecret_core::api::MemberDto;
use twosecret_core::item::{Category, Item};
use twosecret_core::profile::Role;

use crate::components::widgets::*;
use crate::i18n::{category_name, field_label, role_name, t};
use crate::icons::{category_icon, either, vault_icon, Icon, ItemAvatar, VAULT_ICONS};
use crate::platform;
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
        Some(Modal::MoveItem(id)) => rsx! { MoveItemModal { ids: vec![id] } },
        Some(Modal::MoveItems(ids)) => rsx! { MoveItemModal { ids } },
        Some(Modal::RenameItem(id)) => rsx! { RenameItemModal { id } },
        Some(Modal::ShareItem(id)) => rsx! { ShareItemModal { id } },
        Some(Modal::DeleteItem(id)) => rsx! { DeleteItemModal { id } },
        Some(Modal::DeleteItems(ids)) => rsx! { DeleteItemsModal { ids } },
        Some(Modal::Reauth) => rsx! { ReauthModal {} },
        Some(Modal::ForgetDevice) => rsx! { ForgetModal {} },
        Some(Modal::Backup) => rsx! { BackupModal {} },
        Some(Modal::SetUpCode(uri)) => rsx! { SetUpCodeModal { uri } },
    }
}

/// A one-time password from an `otpauth://` link: add it to the account's
/// login (the best fits first), or start a new login with it.
#[component]
fn SetUpCodeModal(uri: String) -> Element {
    let mut query = use_signal(String::new);
    let Ok(totp) = twosecret_core::totp::Totp::parse(&uri) else { return rsx! {} };
    let account =
        [totp.issuer.as_deref(), totp.account.as_deref()].into_iter().flatten().collect::<Vec<_>>().join(" · ");
    let q = query().trim().to_lowercase();
    let mut logins: Vec<(u8, Item)> = {
        let session = SESSION.read();
        let Some(s) = session.as_ref() else { return rsx! {} };
        let writable: Vec<String> = s.vaults().into_iter().filter(|v| v.role.can_write()).map(|v| v.id).collect();
        s.all_items()
            .filter(|(v, i)| !i.is_trashed() && writable.iter().any(|w| w == v))
            .filter(|(_, i)| i.category == Category::Login || i.totp_secret().is_some())
            .filter(|(_, i)| {
                q.is_empty()
                    || i.title.to_lowercase().contains(&q)
                    || i.username().is_some_and(|u| u.to_lowercase().contains(&q))
                    || i.urls.iter().any(|u| u.to_lowercase().contains(&q))
            })
            .map(|(_, i)| (crate::code_setup::fit(i, &totp), i.clone()))
            .collect()
    };
    logins.sort_by_key(|(fit, i)| (std::cmp::Reverse(*fit), i.title.to_lowercase()));
    logins.truncate(20);

    let new_login = {
        let uri = uri.clone();
        move |_| {
            let Some(vault_id) = SESSION.peek().as_ref().and_then(|s| s.default_vault_id()) else {
                toast_err(t("err.no_vault"));
                return;
            };
            let Ok(totp) = twosecret_core::totp::Totp::parse(&uri) else { return };
            let title = totp.issuer.clone().or_else(|| totp.account.clone()).unwrap_or_default();
            let mut item = Item::new(Category::Login, &title);
            if let Some(account) = &totp.account {
                item.set_value("username", account);
            }
            item.set_totp(&uri);
            item.urls.push(String::new());
            clear_search();
            *NAV.write() = Nav::All;
            *SELECTED.write() = None;
            *EDITING.write() = Some(Draft { item, vault_id, is_new: true });
            *PANE.write() = Pane::Detail;
            close();
        }
    };
    rsx! {
        ModalFrame { title: t("code.setup_title"),
            footer: rsx! {
                button { class: "btn", onclick: move |_| close(), {t("common.cancel")} }
                button { class: "btn primary", onclick: new_login, Icon { name: "plus", size: 15 } {t("code.new_login")} }
            },
            if !account.is_empty() { p { style: "margin-top:0", strong { "{account}" } } }
            p { class: "muted", style: "margin-top:0;line-height:1.5", {t("code.setup_explain")} }
            div { class: "form-group",
                input { class: "input", r#type: "search", placeholder: t("code.search"), value: "{query}",
                    oninput: move |e| query.set(e.value()) }
            }
            if logins.is_empty() {
                p { class: "muted", {t("list.no_results")} }
            }
            div { class: "pick-list",
                for (_, item) in logins {
                    button { class: "choice compact", key: "{item.id}",
                        onclick: {
                            let (id, uri) = (item.id.clone(), uri.clone());
                            move |_| {
                                if mutate(|s| s.set_totp(&id, &uri)).is_some() {
                                    close();
                                    open_item(&id);
                                    toast(t("code.added"));
                                }
                            }
                        },
                        ItemAvatar { category: item.category, title: item.title.clone(), size: 32,
                            icon: item.icon.as_ref().and_then(|i| i.safe_image()).map(str::to_string) }
                        div {
                            div { class: "t", "{item.title}" }
                            div { class: "d",
                                if item.totp_secret().is_some() { {t("code.replaces")} } else { {item.username().unwrap_or_default().to_string()} }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// An encrypted backup of all vaults, from the reminder.
#[component]
fn BackupModal() -> Element {
    let mut password = use_signal(String::new);
    let mut confirm = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    let mut submit = move || {
        let (pw, cf) = (password(), confirm());
        if let Err(e) = crate::components::settings::check_backup_password(&pw, &cf) {
            error.set(Some(e));
            return;
        }
        spawn(async move {
            match save_backup("encrypted", pw).await {
                Ok(w) => {
                    close();
                    toast(&format!("{} {w}", t("toast.saved_to")));
                }
                Err(e) => error.set(Some(e)),
            }
        });
    };
    rsx! {
        ModalFrame { title: t("backup.make"),
            footer: rsx! {
                button { class: "btn", onclick: move |_| close(), {t("common.cancel")} }
                button { class: "btn primary", onclick: move |_| submit(), Icon { name: "download", size: 15 } {t("backup.make")} }
            },
            p { class: "muted", style: "margin-top:0;line-height:1.5", {t("backup.explain")} }
            if let Some(err) = error() { div { class: "error-box", "{err}" } }
            div { class: "form-group",
                label { class: "label", {t("export.password")} }
                PasswordInput { value: password(), oninput: move |v| password.set(v), autofocus: true }
            }
            div { class: "form-group",
                label { class: "label", {t("create.confirm")} }
                PasswordInput { value: confirm(), oninput: move |v| confirm.set(v), onenter: move |_| submit() }
            }
            div { class: "info-box small", {t("backup.password_hint")} }
        }
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
    let shared = existing.as_ref().is_some_and(|v| v.is_shared());
    let mut icon = use_signal(|| existing.as_ref().map(|v| vault_icon(&v.icon, v.is_shared())).unwrap_or("vault"));
    let title = if id.is_some() { t("vault.edit") } else { t("vault.new") };
    let id2 = id.clone();
    let save = move |_| {
        let (n, d, i) = (name(), description(), icon());
        if n.trim().is_empty() {
            return;
        }
        match &id2 {
            Some(id) => {
                let id = id.clone();
                if mutate(|s| s.update_vault(&id, &n, &d, Some(i))).is_some() {
                    close();
                }
            }
            None => {
                let created =
                    mutate(|s| s.create_vault(&n, &d).and_then(|id| s.update_vault(&id, &n, &d, Some(i)).map(|_| id)));
                if let Some(new_id) = created {
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
            div { class: "form-group",
                label { class: "label", {t("vault.icon")} }
                div { class: "icon-grid", role: "radiogroup",
                    for name in VAULT_ICONS {
                        button { key: "{name}", r#type: "button", role: "radio",
                            class: either(icon() == name, "icon-choice selected", "icon-choice"),
                            aria_checked: icon() == name,
                            onclick: move |_| icon.set(name),
                            Icon { name, size: 18 }
                        }
                    }
                }
                if shared {
                    div { class: "muted small", style: "margin-top:6px", {t("vault.icon_shared")} }
                }
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

/// Move one item, or several picked in the list, to another vault.
#[component]
fn MoveItemModal(ids: Vec<String>) -> Element {
    let session = SESSION.peek();
    // The vault they are all in is not offered.
    let current: Vec<String> =
        ids.iter().filter_map(|id| session.as_ref().and_then(|s| s.item_vault(id)).map(str::to_string)).collect();
    let only = current.first().filter(|first| current.iter().all(|v| v == *first)).cloned().unwrap_or_default();
    let vaults: Vec<_> = session
        .as_ref()
        .map(|s| s.vaults().into_iter().filter(|v| v.role.can_write() && v.id != only).collect())
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
                        let ids = ids.clone();
                        move |_| {
                            if let [id] = ids.as_slice() {
                                if let Some(new_id) = mutate(|s| s.move_item(id, &v.id)) {
                                    if SELECTED.peek().as_deref() == Some(id.as_str()) {
                                        *SELECTED.write() = Some(new_id);
                                    }
                                    *PICKED.write() = None;
                                    toast(t("toast.moved"));
                                    close();
                                }
                                return;
                            }
                            // Items already in that vault stay where they are.
                            let moved = mutate(|s| {
                                Ok(ids
                                    .iter()
                                    .filter(|id| s.item_vault(id) != Some(v.id.as_str()) && s.move_item(id, &v.id).is_ok())
                                    .count())
                            });
                            if let Some(n) = moved {
                                if SELECTED.peek().as_ref().is_some_and(|id| ids.contains(id)) {
                                    *SELECTED.write() = None;
                                    *PANE.write() = Pane::List;
                                }
                                *PICKED.write() = None;
                                toast(&t("toast.moved_n").replace("{n}", &n.to_string()));
                                close();
                            }
                        }
                    },
                    Icon { name: vault_icon(&v.icon, v.is_shared()), size: 20 }
                    div { div { class: "t", "{v.name}" } div { class: "d", "{v.item_count} {t(\"vault.items\")}" } }
                }
            }
        }
    }
}

/// How long a new link works.
const LINK_EXPIRY: [(i64, &str); 4] =
    [(3600, "link.hour"), (86_400, "link.day"), (7 * 86_400, "link.week"), (30 * 86_400, "link.month")];
/// How often it can be opened (0: until it expires).
const LINK_VIEWS: [u32; 4] = [1, 3, 10, 0];

/// Share an item at a link for someone without 2Secret
/// (`twosecret_core::share`): pick the fields, how long and how often.
#[component]
fn ShareItemModal(id: String) -> Element {
    let item = SESSION.peek().as_ref().and_then(|s| s.item(&id).cloned());
    let linked = SESSION.peek().as_ref().is_some_and(|s| s.server().is_some());
    // Fields with a value, checked: all but one-time passwords.
    let mut chosen = use_signal(|| {
        item.as_ref()
            .map(|i| {
                i.fields
                    .iter()
                    .filter(|f| !f.value.trim().is_empty())
                    .map(|f| (f.id.clone(), f.kind != twosecret_core::item::FieldKind::Totp))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    });
    let mut notes = use_signal(|| true);
    let mut expires = use_signal(|| 7 * 86_400i64);
    let mut views = use_signal(|| 0u32);
    let mut password = use_signal(String::new);
    let mut error = use_signal(|| None::<String>);
    // The new link and when it expires.
    let mut link = use_signal(|| None::<(String, i64)>);
    let Some(item) = item else { return rsx! {} };
    if !linked {
        return rsx! {
            ModalFrame { title: t("link.title"),
                p { {t("link.needs_server")} }
                button { class: "btn primary", onclick: move |_| { close(); *NAV.write() = Nav::Settings; }, {t("settings.connect")} }
            }
        };
    }

    if let Some((url, expires_at)) = link() {
        let copy_url = url.clone();
        let views_text = match views() {
            0 => String::new(),
            1 => format!(" {}", t("link.ready_once")),
            n => format!(" {}", t("link.ready_n").replace("{n}", &n.to_string())),
        };
        return rsx! {
            ModalFrame { title: t("link.title"),
                footer: rsx! {
                    button { class: "btn primary", onclick: move |_| close(), {t("common.close")} }
                },
                p { class: "small muted",
                    {t("link.ready").replace("{date}", &platform::local_time(expires_at))}
                    "{views_text}"
                }
                div { class: "row",
                    input { class: "input grow mono", readonly: true, value: "{url}" }
                    button { class: "btn primary", onclick: move |_| copy(copy_url.clone(), t("link.link")),
                        Icon { name: "copy", size: 15 }
                        {t("common.copy")}
                    }
                }
                if !password().is_empty() {
                    p { class: "small muted", style: "margin-top:12px", {t("link.password_apart")} }
                }
            }
        };
    }

    let has_notes = !item.notes.trim().is_empty();
    let fields: Vec<_> = item.fields.iter().filter(|f| !f.value.trim().is_empty()).cloned().collect();
    let item_id = id.clone();
    let create = move |_| {
        let Some(session) = session_copy() else { return };
        let Some(item) = session.item(&item_id).cloned() else { return };
        let picked = chosen();
        let keep = move |f: &twosecret_core::item::Field| picked.iter().any(|(id, on)| *on && *id == f.id);
        let shared = twosecret_core::share::SharedItem::from_item(&item, field_label, keep, notes());
        if shared.fields.is_empty() && shared.notes.is_empty() {
            error.set(Some(t("link.nothing").into()));
            return;
        }
        let pw = password();
        let expires_at = twosecret_core::util::now() + expires();
        let max_views = Some(views()).filter(|v| *v > 0);
        error.set(None);
        spawn(async move {
            busy(t("busy.working"));
            let sealed = platform::run_heavy(move || {
                let mut shared = shared;
                let sealed = twosecret_core::share::seal(&shared, Some(pw.as_str()));
                zeroize::Zeroize::zeroize(&mut shared);
                sealed
            })
            .await;
            let result = match sealed {
                Ok(sealed) => twosecret_client::publish_share(
                    &session,
                    &sealed,
                    &item.title,
                    expires_at,
                    max_views,
                    !password.peek().is_empty(),
                )
                .await
                .map_err(|e| client_error(&e)),
                Err(e) => Err(core_error(&e)),
            };
            unbusy();
            match result {
                Ok(url) => link.set(Some((url, expires_at))),
                Err(e) => error.set(Some(e)),
            }
        });
    };

    rsx! {
        ModalFrame { title: format!("{} · {}", t("link.title"), item.title),
            footer: rsx! {
                button { class: "btn", onclick: move |_| close(), {t("common.cancel")} }
                button { class: "btn primary", onclick: create, Icon { name: "share", size: 15 } {t("link.create")} }
            },
            if let Some(err) = error() { div { class: "error-box", "{err}" } }
            p { class: "small muted", {t("link.explain")} }
            label { class: "label", {t("link.what")} }
            for (i, f) in fields.iter().enumerate() {
                label { class: "checkbox", key: "{f.id}",
                    input { r#type: "checkbox", checked: chosen.read().get(i).is_some_and(|(_, on)| *on),
                        onchange: move |e| chosen.with_mut(|c| if let Some(entry) = c.get_mut(i) { entry.1 = e.checked() }),
                    }
                    "{field_label(f)}"
                }
            }
            if has_notes {
                label { class: "checkbox",
                    input { r#type: "checkbox", checked: notes(), onchange: move |e| notes.set(e.checked()) }
                    {t("field.notes")}
                }
            }
            if !item.urls.iter().all(|u| u.trim().is_empty()) {
                p { class: "small muted", style: "margin:6px 0 0", {t("link.websites")} }
            }
            div { class: "row", style: "margin-top:16px;gap:12px;flex-wrap:wrap",
                div { class: "grow",
                    label { class: "label", {t("link.expires")} }
                    select { class: "input",
                        onchange: move |e| if let Ok(v) = e.value().parse() { expires.set(v) },
                        for (seconds, key) in LINK_EXPIRY {
                            option { value: "{seconds}", selected: expires() == seconds, {t(key)} }
                        }
                    }
                }
                div { class: "grow",
                    label { class: "label", {t("link.views")} }
                    select { class: "input",
                        onchange: move |e| if let Ok(v) = e.value().parse() { views.set(v) },
                        for n in LINK_VIEWS {
                            option { value: "{n}", selected: views() == n,
                                match n {
                                    0 => t("link.unlimited").to_string(),
                                    1 => t("link.views_once").to_string(),
                                    n => t("link.views_n").replace("{n}", &n.to_string()),
                                }
                            }
                        }
                    }
                }
            }
            label { class: "label", style: "margin-top:16px", {t("link.password")} }
            input { class: "input", r#type: "password", autocomplete: "new-password",
                placeholder: t("link.password_none"),
                oninput: move |e| password.set(e.value()),
            }
            p { class: "small muted", style: "margin-top:6px", {t("link.password_desc")} }
        }
    }
}

/// A new name for an item.
#[component]
fn RenameItemModal(id: String) -> Element {
    let current = SESSION.peek().as_ref().and_then(|s| s.item(&id).map(|i| i.title.clone())).unwrap_or_default();
    let mut name = use_signal(|| current.clone());
    let save = move || {
        let title = name().trim().to_string();
        if title.is_empty() {
            return;
        }
        let renamed = mutate(|s| {
            let mut item =
                s.item(&id).cloned().ok_or_else(|| twosecret_core::Error::not_found(format!("item {id}")))?;
            item.title = title;
            s.update_item(item)
        });
        if renamed.is_some() {
            toast(t("toast.saved"));
            close();
        }
    };
    let save_key = save.clone();
    let save_click = save;
    rsx! {
        ModalFrame { title: t("item.rename"),
            footer: rsx! {
                button { class: "btn", onclick: move |_| close(), {t("common.cancel")} }
                button { class: "btn primary", disabled: name().trim().is_empty(), onclick: move |_| save_click(), {t("common.save")} }
            },
            label { class: "label", {t("vault.name")} }
            input { class: "input", value: "{name}", autofocus: true, autocapitalize: "sentences",
                oninput: move |e| name.set(e.value()),
                onkeydown: move |e: KeyboardEvent| {
                    if e.key() == Key::Enter {
                        save_key();
                    }
                },
            }
        }
    }
}

/// Delete several items in the trash for good.
#[component]
fn DeleteItemsModal(ids: Vec<String>) -> Element {
    let count = ids.len();
    rsx! {
        ModalFrame { title: t("item.delete_forever"),
            footer: rsx! {
                button { class: "btn", onclick: move |_| close(), {t("common.cancel")} }
                button { class: "btn danger",
                    onclick: move |_| {
                        if let Some(n) = mutate(|s| Ok(ids.iter().filter(|id| s.delete_item(id).is_ok()).count())) {
                            if SELECTED.peek().as_ref().is_some_and(|id| ids.contains(id)) {
                                *SELECTED.write() = None;
                                *PANE.write() = Pane::List;
                            }
                            *PICKED.write() = None;
                            toast(&format!("{n} {}", t("toast.deleted_items")));
                            close();
                        }
                    },
                    {t("common.delete")}
                }
            },
            p { strong { {t("pick.count").replace("{n}", &count.to_string())} } }
            p { class: "muted", {t("item.delete_many_warning")} }
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

    let vid_rotate = id.clone();
    let rotate = move |_| {
        let Some(mut session) = session_copy() else { return };
        let vid = vid_rotate.clone();
        error.set(None);
        spawn(async move {
            busy(t("busy.working"));
            let result = twosecret_client::rotate_vault_key(&mut session, &vid).await;
            unbusy();
            match result {
                Ok(()) => {
                    install_session(session);
                    toast(t("share.rotated"));
                }
                Err(e) => error.set(Some(client_error(&e))),
            }
        });
    };
    let shared = members().is_some_and(|m| m.len() > 1);

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
            if vault.role.can_manage() && shared {
                div { class: "row", style: "margin-top:16px;align-items:flex-start",
                    p { class: "small muted grow", style: "margin:0", {t("share.rotate_desc")} }
                    button { class: "btn", onclick: rotate, Icon { name: "key", size: 15 } {t("share.rotate")} }
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
                div { class: "d", "{member.email} · " span { class: "mono", style: "white-space:nowrap", "{fingerprint}" } }
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
