//! Item editor (create and edit).

use dioxus::prelude::*;
use twosecret_core::item::{Attachment, Category, Field, FieldKind};

use crate::components::item_view::human_size;
use crate::components::widgets::*;
use crate::i18n::{category_name, field_kind_name, field_label, t};
use crate::icons::{either, Icon, ItemAvatar};
use crate::state::*;

fn draft_mut(f: impl FnOnce(&mut Draft)) {
    if let Some(d) = EDITING.write().as_mut() {
        f(d);
    }
}

#[component]
pub fn ItemEditor() -> Element {
    let mut new_kind = use_signal(|| FieldKind::Text);
    let mut tags_text = use_signal(|| EDITING.peek().as_ref().map(|d| d.item.tags.join(", ")).unwrap_or_default());
    let mut error = use_signal(|| None::<String>);
    // Bumped on structural URL changes so uncontrolled inputs are re-created.
    let mut url_rev = use_signal(|| 0u32);
    // Bumped when field values are replaced programmatically (SSH key generation).
    let mut field_rev = use_signal(|| 0u32);
    let draft = EDITING.read().clone();
    let Some(draft) = draft else { return rsx! {} };
    let item = draft.item.clone();
    let vaults: Vec<_> = SESSION
        .read()
        .as_ref()
        .map(|s| s.vaults().into_iter().filter(|v| v.role.can_write()).collect())
        .unwrap_or_default();
    let show_urls = item.category.has_urls() || !item.urls.is_empty();
    let draft_is_new = draft.is_new;
    let title_placeholder = category_name(item.category);
    let heading = if draft.is_new { t("edit.new_title") } else { t("edit.edit_title") };

    let save = move |_| {
        let Some(mut d) = EDITING.peek().clone() else { return };
        d.item.tags = tags_text().split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        if let Some(f) = d.item.fields.iter().find(|f| f.kind == FieldKind::Totp && !f.value.trim().is_empty()) {
            if twosecret_core::totp::Totp::parse(&f.value).is_err() {
                error.set(Some(t("item.invalid_totp").to_string()));
                return;
            }
        }
        if d.item.title.trim().is_empty() && d.item.urls.iter().all(|u| u.trim().is_empty()) {
            error.set(Some(t("edit.err_title").to_string()));
            return;
        }
        let result = if d.is_new {
            let vault = d.vault_id.clone();
            mutate(move |s| s.add_item(&vault, d.item.clone()))
        } else {
            let id = d.item.id.clone();
            mutate(move |s| s.update_item(d.item.clone()).map(|_| id))
        };
        if let Some(id) = result {
            *EDITING.write() = None;
            *SELECTED.write() = Some(id.clone());
            toast(t("toast.saved"));
            fetch_icons(vec![id]);
        }
    };

    rsx! {
        div { class: "toolbar",
            span { class: "grow", style: "font-weight:600", "{heading}" }
            button { class: "btn small",
                onclick: move |_| {
                    let was_new = EDITING.peek().as_ref().is_some_and(|d| d.is_new);
                    *EDITING.write() = None;
                    if was_new { *PANE.write() = Pane::List; }
                },
                {t("common.cancel")}
            }
            button { class: "btn primary small", onclick: save,
                Icon { name: "check", size: 15 }
                {t("common.save")}
            }
        }
        div { class: "detail-scroll",
            div { class: "detail-inner",
                if let Some(err) = error() {
                    div { class: "error-box", "{err}" }
                }
                div { class: "detail-head",
                    ItemAvatar { category: item.category, title: item.title.clone(), size: 56, icon: item.icon.as_ref().and_then(|i| i.safe_image()).map(str::to_string) }
                    div { class: "grow",
                        input { class: "title-input", initial_value: "{item.title}", placeholder: "{title_placeholder}", autofocus: draft.is_new,
                            onmounted: move |e: MountedEvent| async move { if draft_is_new { let _ = e.set_focus(true).await; } },
                            oninput: move |e| draft_mut(|d| d.item.title = e.value()) }
                        if draft.is_new && vaults.len() > 1 {
                            select { class: "input", style: "width:auto;margin-top:6px",
                                onchange: move |e| draft_mut(|d| d.vault_id = e.value()),
                                for v in vaults.iter() {
                                    option { key: "{v.id}", value: "{v.id}", selected: v.id == draft.vault_id, "{v.name}" }
                                }
                            }
                        }
                    }
                }
                div { class: "section",
                    for (idx , f) in item.fields.iter().enumerate() {
                        EditField { key: "{f.id}-{field_rev}", idx, field: f.clone(), title: item.title.clone() }
                    }
                    div { class: "add-field-row",
                        if item.category == Category::SshKey && item.value("private_key").is_none_or(|v| v.trim().is_empty()) {
                            button { class: "btn small primary",
                                onclick: move |_| {
                                    let mut failed = None;
                                    draft_mut(|d| {
                                        let comment = if d.item.title.trim().is_empty() { "2secret".to_string() } else { d.item.title.clone() };
                                        if let Err(e) = twosecret_core::ssh::fill_item(&mut d.item, &comment) {
                                            failed = Some(e.to_string());
                                        }
                                    });
                                    match failed {
                                        Some(e) => toast_err(&e),
                                        None => field_rev += 1,
                                    }
                                },
                                Icon { name: "key", size: 14 }
                                {t("edit.generate_ssh")}
                            }
                        }
                        select { class: "input", style: "width:auto",
                            onchange: move |e| {
                                if let Some(k) = FieldKind::parse(&e.value()) { new_kind.set(k); }
                            },
                            for k in FieldKind::ALL {
                                option { key: "{k.id()}", value: "{k.id()}", selected: k == new_kind(), {field_kind_name(k)} }
                            }
                        }
                        button { class: "btn small",
                            onclick: move |_| {
                                let kind = new_kind();
                                draft_mut(|d| d.item.fields.push(Field::custom("", kind, "")));
                            },
                            Icon { name: "plus", size: 14 }
                            {t("edit.add_field")}
                        }
                    }
                }
                if show_urls {
                    div { class: "section",
                        div { class: "section-title", {t("field.websites")} }
                        div { class: "section-body col",
                            for (i , url) in item.urls.iter().enumerate() {
                                div { class: "row", key: "u{i}-{url_rev}",
                                    input { class: "input", initial_value: "{url}", placeholder: "https://example.com", autocapitalize: "off",
                                        oninput: move |e| draft_mut(|d| { if let Some(u) = d.item.urls.get_mut(i) { *u = e.value(); } }) }
                                    button { class: "icon-btn", onclick: move |_| { draft_mut(|d| { if i < d.item.urls.len() { d.item.urls.remove(i); } }); url_rev += 1; },
                                        Icon { name: "x", size: 16 }
                                    }
                                }
                            }
                            div {
                                button { class: "btn small", onclick: move |_| draft_mut(|d| d.item.urls.push(String::new())),
                                    Icon { name: "plus", size: 14 }
                                    {t("edit.add_website")}
                                }
                            }
                        }
                    }
                } else {
                    div { style: "margin-bottom:16px",
                        button { class: "btn small", onclick: move |_| draft_mut(|d| d.item.urls.push(String::new())),
                            Icon { name: "globe", size: 14 }
                            {t("edit.add_website")}
                        }
                    }
                }
                div { class: "section",
                    div { class: "section-title", {t("field.notes")} }
                    div { class: "section-body",
                        textarea { class: "input", rows: if item.category == Category::SecureNote { "12" } else { "4" },
                            initial_value: "{item.notes}", oninput: move |e| draft_mut(|d| d.item.notes = e.value()) }
                    }
                }
                div { class: "section",
                    div { class: "section-title", {t("field.tags")} }
                    div { class: "section-body",
                        input { class: "input", initial_value: "{tags_text}", placeholder: t("edit.tags_hint"), oninput: move |e| tags_text.set(e.value()) }
                        label { class: "checkbox", style: "margin-top:12px",
                            input { r#type: "checkbox", checked: item.favorite, onchange: move |e| draft_mut(|d| d.item.favorite = e.checked()) }
                            span { {t("item.favorite")} }
                        }
                    }
                }
                div { class: "section",
                    div { class: "section-title", {t("field.attachments")} }
                    div { class: "section-body col",
                        for (i , a) in item.attachments.iter().enumerate() {
                            div { class: "row", key: "{a.id}",
                                Icon { name: "paperclip", size: 15 }
                                span { class: "grow", "{a.name} ({human_size(a.size)})" }
                                button { class: "icon-btn", onclick: move |_| draft_mut(|d| { if i < d.item.attachments.len() { d.item.attachments.remove(i); } }),
                                    Icon { name: "x", size: 16 }
                                }
                            }
                        }
                        input { r#type: "file", multiple: true,
                            onchange: move |e| {
                                let files = e.files();
                                spawn(async move {
                                    for file in files {
                                        let name = file.name();
                                        match file.read_bytes().await {
                                            Ok(bytes) => {
                                                let mime = mime_for(&name);
                                                match Attachment::new(&name, mime, &bytes) {
                                                    Ok(a) => draft_mut(|d| d.item.attachments.push(a)),
                                                    Err(err) => toast_err(&err.to_string()),
                                                }
                                            }
                                            Err(err) => toast_err(&err.to_string()),
                                        }
                                    }
                                });
                            }
                        }
                        div { class: "small muted", {t("edit.attach_hint")} }
                    }
                }
            }
        }
    }
}

fn mime_for(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "txt" | "md" => "text/plain",
        "json" => "application/json",
        "pem" | "key" | "pub" => "application/x-pem-file",
        _ => "application/octet-stream",
    }
}

/// A concealed value that may span several lines. Hidden until revealed;
/// revealing shows an editable text area.
#[component]
fn SecretArea(value: String, oninput: EventHandler<String>) -> Element {
    let mut reveal = use_signal(|| value.is_empty());
    rsx! {
        div { class: "input-group secret-area",
            if reveal() {
                textarea { class: "input mono", initial_value: "{value}", autocomplete: "off", spellcheck: "false",
                    autocapitalize: "off", oninput: move |e| oninput.call(e.value()) }
            } else {
                div { class: "input masked", onclick: move |_| reveal.set(true), "••••••••••" }
            }
            button { class: "icon-btn", r#type: "button", title: t("common.reveal"), onclick: move |_| reveal.toggle(),
                Icon { name: either(reveal(), "eye-off", "eye"), size: 16 }
            }
        }
    }
}

#[component]
fn EditField(idx: usize, field: Field, title: String) -> Element {
    let label = field_label(&field);
    let custom = field.is_custom();
    let value = field.value.clone();
    let set = move |v: String| {
        draft_mut(|d| {
            if let Some(f) = d.item.fields.get_mut(idx) {
                f.value = v;
            }
        })
    };
    let input_type = match field.kind {
        FieldKind::Email => "email",
        FieldKind::Url => "url",
        FieldKind::Phone => "tel",
        FieldKind::Date => "date",
        _ => "text",
    };
    let placeholder = match field.kind {
        FieldKind::MonthYear => "MM/YYYY".to_string(),
        FieldKind::Totp => t("edit.totp_hint").to_string(),
        _ => String::new(),
    };
    rsx! {
        div { class: "edit-field",
            div { class: "col", style: "gap:4px;min-width:0",
                if custom {
                    input { class: "label-input", initial_value: "{field.label}", placeholder: t("edit.field_label"),
                        oninput: move |e| draft_mut(|d| { if let Some(f) = d.item.fields.get_mut(idx) { f.label = e.value(); } }) }
                } else {
                    div { class: "label-input", "{label}" }
                }
                match field.kind {
                    // Private keys span several lines, which single-line inputs would drop.
                    FieldKind::Concealed if field.id == "private_key" || value.contains('\n') => rsx! {
                        SecretArea { value: value.clone(), oninput: set }
                    },
                    FieldKind::Concealed => rsx! {
                        PasswordInput { value: value.clone(), oninput: set, generate: field.is_password(),
                            rules: field.generator.clone(),
                            onrules: move |rules| draft_mut(|d| { if let Some(f) = d.item.fields.get_mut(idx) { f.generator = Some(rules); } }) }
                        if field.is_password() {
                            StrengthMeter { password: value.clone(), inputs: vec![title.clone()] }
                        }
                    },
                    FieldKind::Multiline => rsx! {
                        textarea { class: "input", initial_value: "{value}", oninput: move |e| set(e.value()) }
                    },
                    _ => rsx! {
                        input { class: if field.kind == FieldKind::Totp { "input mono" } else { "input" }, r#type: input_type,
                            initial_value: "{value}", placeholder: "{placeholder}", autocapitalize: "off", spellcheck: "false",
                            oninput: move |e| set(e.value()) }
                    },
                }
            }
            button { class: "icon-btn", title: t("common.remove"), style: "align-self:end",
                onclick: move |_| draft_mut(|d| { if idx < d.item.fields.len() { d.item.fields.remove(idx); } }),
                Icon { name: "x", size: 16 }
            }
        }
    }
}
