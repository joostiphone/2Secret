//! Read-only item view.

use dioxus::prelude::*;
use twosecret_core::item::{Field, FieldKind};
use twosecret_core::strength::{estimate, StrengthLevel};

use crate::components::widgets::*;
use crate::i18n::{category_name, field_label, t};
use crate::icons::{either, Icon, ItemAvatar};
use crate::platform;
use crate::state::*;

#[component]
pub fn ItemView(id: String) -> Element {
    let mut menu = use_signal(|| false);
    let mut show_history = use_signal(|| false);
    let session = SESSION.read();
    let Some(s) = session.as_ref() else { return rsx! {} };
    let Some(item) = s.item(&id).cloned() else { return rsx! {} };
    let vault_id = s.item_vault(&id).unwrap_or_default().to_string();
    let vault = s.vault(&vault_id);
    let can_write = vault.as_ref().is_some_and(|v| v.role.can_write());
    let vault_name = vault.map(|v| v.name).unwrap_or_default();
    let reused = item
        .password()
        .map(|pw| s.all_items().filter(|(_, o)| o.id != item.id && !o.is_trashed() && o.password() == Some(pw)).count())
        .unwrap_or(0);
    drop(session);

    let weak =
        item.password().map(|pw| estimate(pw, &[item.title.as_str()]).level <= StrengthLevel::Weak).unwrap_or(false);
    let breached = BREACHES.read().as_ref().and_then(|b| b.get(&item.id).copied());
    let trashed = item.is_trashed();
    let fav = item.favorite;
    let cat_name = category_name(item.category);

    let mut sections: Vec<(String, Vec<Field>)> = Vec::new();
    for f in item.fields.iter().filter(|f| !f.value.trim().is_empty()) {
        match sections.iter_mut().find(|(s, _)| *s == f.section) {
            Some((_, list)) => list.push(f.clone()),
            None => sections.push((f.section.clone(), vec![f.clone()])),
        }
    }

    let id_fav = id.clone();
    let id_edit = id.clone();
    let id_menu = id.clone();

    rsx! {
        div { class: "toolbar",
            button { class: "icon-btn mobile-only", onclick: move |_| *PANE.write() = Pane::List, Icon { name: "chevron-left" } }
            span { class: "spacer" }
            if crate::extension::ENABLED && !trashed && (item.password().is_some() || item.username().is_some()) {
                button { class: "btn primary small",
                    onclick: { let id = id.clone(); move |_| fill_item(&id) },
                    Icon { name: "zap", size: 15 }
                    {t("ext.fill")}
                }
            }
            if !trashed {
                button { class: if fav { "icon-btn active" } else { "icon-btn" }, title: t("item.favorite"), disabled: !can_write,
                    onclick: move |_| { mutate(|s| s.set_favorite(&id_fav, !fav)); },
                    Icon { name: "star" }
                }
            }
            if can_write && !trashed {
                button { class: "btn small",
                    onclick: move |_| {
                        let Some(draft) = SESSION.peek().as_ref().and_then(|s| {
                            Some(Draft { item: s.item(&id_edit)?.clone(), vault_id: s.item_vault(&id_edit)?.to_string(), is_new: false })
                        }) else { return };
                        *EDITING.write() = Some(draft);
                    },
                    Icon { name: "edit", size: 15 }
                    {t("common.edit")}
                }
            }
            if trashed && can_write {
                button { class: "btn small",
                    onclick: {
                        let id = id.clone();
                        move |_| { if mutate(|s| s.restore_item(&id)).is_some() { toast(t("toast.restored")); } }
                    },
                    Icon { name: "restore", size: 15 }
                    {t("item.restore")}
                }
            }
            if can_write {
                div { class: "rel",
                    button { class: "icon-btn", onclick: move |_| menu.toggle(), Icon { name: "more" } }
                    if menu() {
                        div { class: "menu", onmouseleave: move |_| menu.set(false),
                            if !trashed {
                                button {
                                    onclick: {
                                        let id = id_menu.clone();
                                        move |_| {
                                            menu.set(false);
                                            if let Some(new_id) = mutate(|s| s.duplicate_item(&id)) {
                                                *SELECTED.write() = Some(new_id);
                                                toast(t("toast.duplicated"));
                                            }
                                        }
                                    },
                                    Icon { name: "duplicate", size: 16 }
                                    {t("item.duplicate")}
                                }
                                button {
                                    onclick: {
                                        let id = id_menu.clone();
                                        move |_| { menu.set(false); *MODAL.write() = Some(Modal::MoveItem(id.clone())); }
                                    },
                                    Icon { name: "folder", size: 16 }
                                    {t("item.move")}
                                }
                                button { class: "danger",
                                    onclick: {
                                        let id = id_menu.clone();
                                        move |_| {
                                            menu.set(false);
                                            if mutate(|s| s.trash_item(&id)).is_some() {
                                                *SELECTED.write() = None;
                                                *PANE.write() = Pane::List;
                                                toast(t("toast.trashed"));
                                            }
                                        }
                                    },
                                    Icon { name: "trash", size: 16 }
                                    {t("item.trash")}
                                }
                            } else {
                                button { class: "danger",
                                    onclick: {
                                        let id = id_menu.clone();
                                        move |_| { menu.set(false); *MODAL.write() = Some(Modal::DeleteItem(id.clone())); }
                                    },
                                    Icon { name: "trash", size: 16 }
                                    {t("item.delete_forever")}
                                }
                            }
                        }
                    }
                }
            }
        }
        div { class: "detail-scroll",
            div { class: "detail-inner",
                div { class: "detail-head",
                    ItemAvatar { category: item.category, title: item.title.clone(), size: 56 }
                    div { class: "grow",
                        h1 { "{item.title}" }
                        div { class: "sub", "{cat_name} · {vault_name}" }
                    }
                }
                if trashed {
                    div { class: "warn-box", {t("item.in_trash")} }
                }
                if let Some(count) = breached {
                    div { class: "error-box", "{t(\"wt.breached_item\")} ({count}×)" }
                }
                if weak {
                    div { class: "warn-box", {t("wt.weak_item")} }
                }
                if reused > 0 {
                    div { class: "warn-box", "{t(\"wt.reused_item\")} ({reused})" }
                }
                for (title , fields) in sections {
                    div { class: "section", key: "sec-{title}",
                        if !title.is_empty() {
                            div { class: "section-title", "{title}" }
                        }
                        for f in fields {
                            FieldRow { key: "{f.id}", field: f.clone(), item_title: item.title.clone() }
                        }
                    }
                }
                if !item.urls.is_empty() {
                    div { class: "section",
                        for (i , url) in item.urls.iter().enumerate() {
                            div { class: "field", key: "url-{i}",
                                div { class: "grow",
                                    div { class: "fl", {t("field.website")} }
                                    div { class: "fv",
                                        a { href: "#", onclick: { let u = url.clone(); move |e: MouseEvent| { e.prevent_default(); platform::open_url(&u); } }, "{url}" }
                                    }
                                }
                                div { class: "actions",
                                    button { class: "icon-btn", title: t("item.open"), onclick: { let u = url.clone(); move |_| platform::open_url(&u) },
                                        Icon { name: "external", size: 16 }
                                    }
                                    button { class: "icon-btn", title: t("common.copy"), onclick: { let u = url.clone(); move |_| copy(u.clone(), t("field.website")) },
                                        Icon { name: "copy", size: 16 }
                                    }
                                }
                            }
                        }
                    }
                }
                if !item.notes.trim().is_empty() {
                    div { class: "section",
                        div { class: "section-title", {t("field.notes")} }
                        div { class: "section-body", div { class: "fv", style: "white-space:pre-wrap;word-break:break-word", "{item.notes}" } }
                    }
                }
                if !item.tags.is_empty() {
                    div { class: "section",
                        div { class: "section-title", {t("field.tags")} }
                        div { class: "section-body",
                            div { class: "tags",
                                for tag in item.tags.iter() {
                                    button { class: "tag", key: "{tag}",
                                        onclick: { let tag = tag.clone(); move |_| { *NAV.write() = Nav::Tag(tag.clone()); *PANE.write() = Pane::List; } },
                                        "{tag}"
                                    }
                                }
                            }
                        }
                    }
                }
                if !item.attachments.is_empty() {
                    div { class: "section",
                        div { class: "section-title", {t("field.attachments")} }
                        for a in item.attachments.iter() {
                            div { class: "field", key: "{a.id}",
                                Icon { name: "paperclip", size: 16 }
                                div { class: "grow",
                                    div { "{a.name}" }
                                    div { class: "small muted", "{human_size(a.size)}" }
                                }
                                button { class: "icon-btn", title: t("common.download"),
                                    onclick: {
                                        let a = a.clone();
                                        move |_| {
                                            let a = a.clone();
                                            spawn(async move {
                                                match a.bytes() {
                                                    Ok(bytes) => match platform::save_file(&a.name, &a.mime, &bytes).await {
                                                        Ok(w) => toast(&format!("{} {w}", t("toast.saved_to"))),
                                                        Err(e) => toast_err(&e),
                                                    },
                                                    Err(e) => toast_err(&e.to_string()),
                                                }
                                            });
                                        }
                                    },
                                    Icon { name: "download", size: 16 }
                                }
                            }
                        }
                    }
                }
                if !item.password_history.is_empty() {
                    div { class: "section",
                        div { class: "section-title row",
                            span { class: "grow", {t("item.password_history")} }
                            button { class: "btn ghost small", onclick: move |_| show_history.toggle(),
                                if show_history() { {t("common.hide")} } else { {t("common.show")} }
                            }
                        }
                        if show_history() {
                            div { class: "section-body",
                                for (i , h) in item.password_history.iter().enumerate() {
                                    div { class: "history-row", key: "h{i}",
                                        ColoredPassword { value: h.value.clone() }
                                        div { class: "row",
                                            span { class: "muted", "{platform::local_time(h.changed_at)}" }
                                            button { class: "icon-btn", onclick: { let v = h.value.clone(); move |_| copy(v.clone(), t("field.password")) },
                                                Icon { name: "copy", size: 14 }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                div { class: "meta",
                    div { "{t(\"item.modified\")} {platform::local_time(item.updated_at)} · {t(\"item.created\")} {platform::local_time(item.created_at)}" }
                    if let Some(ts) = item.password_changed_at {
                        div { "{t(\"item.password_changed\")} {platform::local_time(ts)}" }
                    }
                }
            }
        }
    }
}

pub fn human_size(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / 1024.0 / 1024.0)
    }
}

#[component]
fn FieldRow(field: Field, item_title: String) -> Element {
    let mut revealed = use_signal(|| false);
    let label = field_label(&field);
    let value = field.value.clone();
    let copy_value = value.clone();
    let copy_label = label.clone();
    match field.kind {
        FieldKind::Totp => rsx! {
            div { class: "field",
                div { class: "grow",
                    div { class: "fl", "{label}" }
                    TotpCode { secret: value }
                }
            }
        },
        _ => {
            let concealed = field.kind == FieldKind::Concealed;
            let is_password = concealed
                && matches!(
                    field.id.as_str(),
                    "password" | "wireless_password" | "credential" | "base_station_password" | "passphrase"
                );
            rsx! {
                div { class: "field",
                    div { class: "grow",
                        div { class: "fl", "{label}" }
                        if concealed && !revealed() {
                            div { class: "fv concealed", "••••••••••" }
                        } else if concealed {
                            div { class: "fv pw", ColoredPassword { value: value.clone() } }
                        } else if field.kind == FieldKind::Url {
                            div { class: "fv", a { href: "#", onclick: { let v = value.clone(); move |e: MouseEvent| { e.prevent_default(); platform::open_url(&v); } }, "{value}" } }
                        } else if field.kind == FieldKind::Email {
                            div { class: "fv", a { href: "mailto:{value}", "{value}" } }
                        } else {
                            div { class: "fv", "{value}" }
                        }
                        if is_password && revealed() {
                            StrengthMeter { password: value.clone(), inputs: vec![item_title.clone()] }
                        }
                    }
                    div { class: "actions",
                        if concealed {
                            button { class: "icon-btn", title: t("common.reveal"), onclick: move |_| revealed.toggle(),
                                Icon { name: either(revealed(), "eye-off", "eye"), size: 16 }
                            }
                        }
                        button { class: "icon-btn", title: t("common.copy"), onclick: move |_| copy(copy_value.clone(), &copy_label),
                            Icon { name: "copy", size: 16 }
                        }
                    }
                }
            }
        }
    }
}
