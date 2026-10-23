//! What can be done with an item or a vault from a list: the menu that a long
//! press (phones and tablets, `LONG_PRESS_JS` in lib.rs) or a right click
//! opens, and the bar for the items picked to act on together.

use std::collections::HashSet;

use dioxus::prelude::*;
use twosecret_core::totp::Totp;

use crate::components::shell::go;
use crate::i18n::t;
use crate::icons::{either, Icon};
use crate::state::*;

/// Opens the menu of an item or a vault where the long press or the click was.
pub fn open_menu(target: MenuFor, e: &MouseEvent) {
    e.prevent_default();
    if PICKED.peek().is_some() {
        return;
    }
    let point = e.client_coordinates();
    *MENU.write() = Some(Menu { target, x: point.x, y: point.y });
}

/// What an entry of the menu does.
#[derive(Clone, Copy, PartialEq)]
enum Action {
    CopyUsername,
    CopyPassword,
    CopyCode,
    Favorite(bool),
    Edit,
    Rename,
    Move,
    Duplicate,
    ShareLink,
    Pick,
    Trash,
    Restore,
    DeleteForever,
    NewItem,
    EditVault,
    ShareVault,
    DeleteVault,
}

#[derive(Clone, PartialEq)]
struct Entry {
    action: Action,
    icon: &'static str,
    label: String,
    danger: bool,
    /// Entries of another group are set apart by a line.
    group: u8,
}

fn entry(action: Action, icon: &'static str, label: &str, group: u8) -> Entry {
    let danger = matches!(action, Action::Trash | Action::DeleteForever | Action::DeleteVault);
    Entry { action, icon, label: label.to_string(), danger, group }
}

/// The heading and the entries of the menu of an item.
fn item_menu(id: &str) -> Option<(String, Vec<Entry>)> {
    let session = SESSION.peek();
    let s = session.as_ref()?;
    let item = s.item(id)?;
    let can_write = s.item_vault(id).and_then(|v| s.vault(v)).is_some_and(|v| v.role.can_write());
    let mut entries = Vec::new();
    if item.is_trashed() {
        if can_write {
            entries.push(entry(Action::Restore, "restore", t("item.restore"), 0));
        }
        entries.push(entry(Action::Pick, "check-square", t("pick.select"), 1));
        if can_write {
            entries.push(entry(Action::DeleteForever, "trash", t("item.delete_forever"), 2));
        }
        return Some((item.title.clone(), entries));
    }
    if item.username().is_some_and(|u| !u.is_empty()) {
        entries.push(entry(Action::CopyUsername, "user", t("menu.copy_username"), 0));
    }
    if item.password().is_some_and(|p| !p.is_empty()) {
        entries.push(entry(Action::CopyPassword, "key", t("menu.copy_password"), 0));
    }
    if item.totp_secret().is_some() {
        entries.push(entry(Action::CopyCode, "clock", t("menu.copy_code"), 0));
    }
    if can_write {
        let favorite = if item.favorite { t("menu.unfavorite") } else { t("menu.favorite") };
        entries.push(entry(Action::Favorite(!item.favorite), "star", favorite, 1));
        entries.push(entry(Action::Edit, "edit", t("common.edit"), 1));
        entries.push(entry(Action::Rename, "type", t("item.rename"), 1));
        entries.push(entry(Action::Move, "folder", t("item.move"), 1));
        entries.push(entry(Action::Duplicate, "duplicate", t("item.duplicate"), 1));
        entries.push(entry(Action::ShareLink, "share", t("link.menu"), 1));
    }
    entries.push(entry(Action::Pick, "check-square", t("pick.select"), 2));
    if can_write {
        entries.push(entry(Action::Trash, "trash", t("item.trash"), 3));
    }
    Some((item.title.clone(), entries))
}

/// The heading and the entries of the menu of a vault.
fn vault_menu(id: &str) -> Option<(String, Vec<Entry>)> {
    let session = SESSION.peek();
    let s = session.as_ref()?;
    let vault = s.vault(id)?;
    let linked = s.server().is_some();
    let mut entries = Vec::new();
    if vault.role.can_write() {
        entries.push(entry(Action::NewItem, "plus", t("vault.new_item"), 0));
    }
    if vault.role.can_manage() {
        entries.push(entry(Action::EditVault, "edit", t("vault.edit"), 1));
        if linked {
            entries.push(entry(Action::ShareVault, "share", t("vault.share"), 1));
        }
    }
    let delete = if vault.is_owner { t("vault.delete") } else { t("vault.leave") };
    entries.push(entry(Action::DeleteVault, "trash", delete, 2));
    Some((vault.name.clone(), entries))
}

fn run(target: &MenuFor, action: Action) {
    *MENU.write() = None;
    match target {
        MenuFor::Item(id) => run_for_item(id, action),
        MenuFor::Vault(id) => match action {
            Action::NewItem => {
                go(Nav::Vault(id.clone()));
                *MODAL.write() = Some(Modal::NewItem);
            }
            Action::EditVault => *MODAL.write() = Some(Modal::EditVault(id.clone())),
            Action::ShareVault => *MODAL.write() = Some(Modal::ShareVault(id.clone())),
            Action::DeleteVault => *MODAL.write() = Some(Modal::DeleteVault(id.clone())),
            _ => {}
        },
    }
}

fn run_for_item(id: &str, action: Action) {
    let id = id.to_string();
    // Values to copy are read here and not kept.
    let value = |f: fn(&twosecret_core::item::Item) -> Option<String>| SESSION.peek().as_ref()?.item(&id).and_then(f);
    match action {
        Action::CopyUsername => {
            if let Some(v) = value(|i| i.username().map(str::to_string)) {
                copy(v, t("field.username"));
            }
        }
        Action::CopyPassword => {
            if let Some(v) = value(|i| i.password().map(str::to_string)) {
                copy(v, t("field.password"));
            }
        }
        Action::CopyCode => {
            if let Some(v) = value(|i| Totp::parse(i.totp_secret()?).ok().map(|totp| totp.now().0)) {
                copy(v, t("field.totp"));
            }
        }
        Action::Favorite(on) => {
            mutate(|s| s.set_favorite(&id, on));
        }
        Action::Edit => {
            let draft = SESSION.peek().as_ref().and_then(|s| {
                Some(Draft { item: s.item(&id)?.clone(), vault_id: s.item_vault(&id)?.to_string(), is_new: false })
            });
            if let Some(draft) = draft {
                if NAV.peek().is_page() {
                    *NAV.write() = Nav::All;
                }
                *SELECTED.write() = Some(id);
                *EDITING.write() = Some(draft);
                *PANE.write() = Pane::Detail;
            }
        }
        Action::Rename => *MODAL.write() = Some(Modal::RenameItem(id)),
        Action::Move => *MODAL.write() = Some(Modal::MoveItem(id)),
        Action::Duplicate => {
            if mutate(|s| s.duplicate_item(&id)).is_some() {
                toast(t("toast.duplicated"));
            }
        }
        Action::ShareLink => *MODAL.write() = Some(Modal::ShareItem(id)),
        Action::Pick => {
            if NAV.peek().is_page() {
                go(Nav::All);
            }
            *PANE.write() = Pane::List;
            *PICKED.write() = Some(HashSet::from([id]));
        }
        Action::Trash => {
            if mutate(|s| s.trash_item(&id)).is_some() {
                leave_item(&id);
                toast(t("toast.trashed"));
            }
        }
        Action::Restore => {
            if mutate(|s| s.restore_item(&id)).is_some() {
                leave_item(&id);
                toast(t("toast.restored"));
            }
        }
        Action::DeleteForever => *MODAL.write() = Some(Modal::DeleteItem(id)),
        _ => {}
    }
}

/// The item has left the list: no longer shown either.
fn leave_item(id: &str) {
    if SELECTED.peek().as_deref() == Some(id) {
        *SELECTED.write() = None;
        *PANE.write() = Pane::List;
    }
}

/// The open menu: next to the pointer on a computer, a sheet at the bottom of
/// the screen on a phone (style.css). A tap or click outside closes it.
#[component]
pub fn ContextMenu() -> Element {
    let Some(menu) = MENU.read().clone() else { return rsx! {} };
    let found = match &menu.target {
        MenuFor::Item(id) => item_menu(id),
        MenuFor::Vault(id) => vault_menu(id),
    };
    let Some((title, entries)) = found else { return rsx! {} };
    let x = menu.x.round();
    let y = menu.y.round();
    let close = move |_| *MENU.write() = None;
    rsx! {
        div { class: "ctx-backdrop", onclick: close,
            oncontextmenu: move |e| {
                e.prevent_default();
                *MENU.write() = None;
            },
        }
        // Focused, so that Escape (in lib.rs) closes it.
        div { class: "ctx-menu", role: "menu", tabindex: "-1", style: "--x:{x}px;--y:{y}px",
            onmounted: move |e: MountedEvent| async move {
                let _ = e.data().set_focus(true).await;
            },
            div { class: "ctx-head", "{title}" }
            for (i , e) in entries.iter().enumerate() {
                button { key: "{i}", role: "menuitem",
                    // A line above the first entry of a group.
                    class: match (e.danger, i > 0 && entries[i - 1].group != e.group) {
                        (true, true) => "danger sep",
                        (true, false) => "danger",
                        (false, true) => "sep",
                        (false, false) => "",
                    },
                    onclick: {
                        let target = menu.target.clone();
                        let action = e.action;
                        move |_| run(&target, action)
                    },
                    Icon { name: e.icon, size: 17 }
                    span { "{e.label}" }
                }
            }
        }
    }
}

/// Picks an item to act on with others, or drops it again.
pub fn toggle_pick(id: &str) {
    let mut picked = PICKED.write();
    let set = picked.get_or_insert_with(HashSet::new);
    if !set.remove(id) {
        set.insert(id.to_string());
    }
}

fn picked() -> Vec<String> {
    PICKED.peek().iter().flatten().cloned().collect()
}

fn done(n: usize, text: &str) {
    *PICKED.write() = None;
    toast(&text.replace("{n}", &n.to_string()));
}

/// The bar under the list while items are picked: what can be done with all
/// of them at once.
#[component]
pub fn PickBar(trash: bool) -> Element {
    let count = PICKED.read().as_ref().map_or(0, |p| p.len());
    let none = count == 0;
    // Favorite them all, unless they all are already.
    let all_favorite = {
        let session = SESSION.read();
        let picked = PICKED.read();
        match (session.as_ref(), picked.as_ref()) {
            (Some(s), Some(p)) if !p.is_empty() => p.iter().all(|id| s.item(id).is_some_and(|i| i.favorite)),
            _ => false,
        }
    };
    rsx! {
        div { class: "pick-bar",
            if trash {
                button { class: "btn small", disabled: none,
                    onclick: move |_| {
                        let ids = picked();
                        if let Some(n) = mutate(|s| Ok(ids.iter().filter(|id| s.restore_item(id).is_ok()).count())) {
                            done(n, t("toast.restored_n"));
                        }
                    },
                    Icon { name: "restore", size: 16 }
                    span { {t("item.restore")} }
                }
                button { class: "btn small danger", disabled: none,
                    onclick: move |_| *MODAL.write() = Some(Modal::DeleteItems(picked())),
                    Icon { name: "trash", size: 16 }
                    span { {t("common.delete")} }
                }
            } else {
                button { class: "btn small", disabled: none,
                    onclick: move |_| {
                        let ids = picked();
                        let on = !all_favorite;
                        if let Some(n) = mutate(|s| Ok(ids.iter().filter(|id| s.set_favorite(id, on).is_ok()).count())) {
                            done(n, if on { t("toast.favorited_n") } else { t("toast.unfavorited_n") });
                        }
                    },
                    Icon { name: "star", size: 16 }
                    span { {either(all_favorite, t("pick.unfavorite"), t("pick.favorite"))} }
                }
                button { class: "btn small", disabled: none,
                    onclick: move |_| *MODAL.write() = Some(Modal::MoveItems(picked())),
                    Icon { name: "folder", size: 16 }
                    span { {t("pick.move")} }
                }
                button { class: "btn small danger", disabled: none,
                    onclick: move |_| {
                        let ids = picked();
                        if let Some(n) = mutate(|s| Ok(ids.iter().filter(|id| s.trash_item(id).is_ok()).count())) {
                            for id in &ids {
                                leave_item(id);
                            }
                            done(n, t("toast.trashed_n"));
                        }
                    },
                    Icon { name: "trash", size: 16 }
                    span { {t("pick.trash")} }
                }
            }
        }
    }
}
