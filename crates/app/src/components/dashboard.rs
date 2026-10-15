//! The dashboard, which the apps open with after unlocking (Settings →
//! Appearance → Start screen): an overview of the vaults that shows no
//! secrets, only counts, the security score, favourites, recent changes and
//! the vaults.

use dioxus::prelude::*;
use twosecret_core::item::{Category, ItemSummary};
use twosecret_core::session::ItemFilter;
use twosecret_core::watchtower::{analyze, IssueKind};

use crate::components::shell::{go, relative_time, sync_summary, BackupReminder};
use crate::components::watchtower::rating;
use crate::i18n::{category_name, issue_title, t};
use crate::icons::{category_icon, either, vault_icon, AccountAvatar, Icon, ItemAvatar};
use crate::platform;
use crate::state::*;

/// How many favourites and recent changes the dashboard lists.
const SHOWN: usize = 5;

/// Show an item in the list of all items.
fn open_item(id: &str) {
    clear_search();
    *NAV.write() = Nav::All;
    *EDITING.write() = None;
    *SELECTED.write() = Some(id.to_string());
    *PANE.write() = Pane::Detail;
}

/// "Good morning, Alex", by the time of day.
fn greeting(name: &str) -> String {
    let Some(first) = name.split_whitespace().next() else { return t("home.welcome").to_string() };
    let key = match platform::local_hour() {
        5..=11 => "home.morning",
        12..=17 => "home.afternoon",
        _ => "home.evening",
    };
    t(key).replace("{name}", first)
}

#[component]
pub fn DashboardPage() -> Element {
    let mut query = use_signal(String::new);
    // Bumped to clear the search field (it keeps its own text while typing).
    let mut reset = use_signal(|| 0u32);
    // Not again for every letter typed in the search field.
    let report = use_memo(|| {
        let breaches = BREACHES.read().clone().unwrap_or_default();
        SESSION.read().as_ref().map(|s| analyze(s.all_items(), &breaches, None)).unwrap_or_default()
    });
    let report = report.read().clone();
    let session = SESSION.read();
    let Some(s) = session.as_ref() else { return rsx! {} };
    let account = s.account().clone();
    let photo = s.avatar();
    let items = s.list(&ItemFilter::default());
    let favorites: Vec<ItemSummary> = items.iter().filter(|i| i.favorite).cloned().collect();
    let mut recent = items.clone();
    recent.sort_by_key(|i| std::cmp::Reverse(i.updated_at));
    recent.truncate(SHOWN);
    let mut categories: Vec<(Category, usize)> = Category::ALL
        .iter()
        .map(|c| (*c, items.iter().filter(|i| i.category == *c).count()))
        .filter(|(_, n)| *n > 0)
        .collect();
    categories.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let vaults = s.vaults();
    let can_add = vaults.iter().any(|v| v.role.can_write());
    let search = query();
    let results = if search.trim().is_empty() {
        None
    } else {
        Some(s.list(&ItemFilter { query: search.clone(), ..Default::default() }))
    };
    let linked = s.server().is_some();
    let last_sync = s.server().and_then(|l| l.last_sync_at);
    drop(session);

    let (dot, sync_text) = sync_summary(linked, last_sync);
    let (words, color) = rating(&report);
    let circumference = 2.0 * std::f64::consts::PI * 26.0;
    let dash = circumference * report.score as f64 / 1000.0;
    let favorite_count = favorites.len();

    rsx! {
        div { class: "toolbar",
            button { class: "icon-btn mobile-only", onclick: move |_| *PANE.write() = Pane::Nav, Icon { name: "menu" } }
            span { class: "grow", style: "font-weight:600;font-size:16px", {t("nav.home")} }
            if can_add {
                button { class: "btn primary small", title: t("item.new"),
                    onclick: move |_| *MODAL.write() = Some(Modal::NewItem),
                    Icon { name: "plus", size: 16 }
                    span { {t("item.new_short")} }
                }
            }
        }
        div { class: "detail-scroll",
            div { class: "dash",
                div { class: "dash-hello",
                    AccountAvatar { name: account.name.clone(), photo, size: 48 }
                    div { class: "grow",
                        h1 { {greeting(&account.name)} }
                        div { class: "sub",
                            span { class: "sync-dot {dot}" }
                            span { "{sync_text}" }
                        }
                    }
                }
                div { class: "search dash-search",
                    Icon { name: "search", size: 16 }
                    for k in [reset()] {
                        input {
                            key: "{k}",
                            placeholder: t("home.search"),
                            initial_value: "{search}",
                            autocapitalize: "off",
                            spellcheck: "false",
                            oninput: move |e| query.set(e.value()),
                        }
                    }
                    if !search.is_empty() {
                        button { class: "icon-btn", style: "width:24px;height:24px", title: t("common.clear"),
                            onclick: move |_| {
                                query.set(String::new());
                                reset += 1;
                            },
                            Icon { name: "x", size: 14 }
                        }
                    }
                }
                BackupReminder {}
                if let Some(results) = results {
                    div { class: "section",
                        if results.is_empty() {
                            div { class: "card-empty", style: "padding-top:16px", {t("list.no_results")} }
                        }
                        for item in results {
                            ItemRow { key: "{item.id}", item: item.clone(), detail: item.subtitle.clone() }
                        }
                    }
                } else if items.is_empty() {
                    div { class: "section",
                        div { class: "empty",
                            Icon { name: "key", size: 40 }
                            h2 { style: "margin:0 0 6px;color:var(--text)", {t("home.empty_title")} }
                            p { style: "margin:0 0 16px", {t("home.empty_desc")} }
                            div { class: "row", style: "justify-content:center",
                                if can_add {
                                    button { class: "btn primary", onclick: move |_| *MODAL.write() = Some(Modal::NewItem),
                                        Icon { name: "plus", size: 16 }
                                        {t("item.new")}
                                    }
                                }
                                if !crate::extension::ENABLED {
                                    button { class: "btn", onclick: move |_| go(Nav::Settings),
                                        Icon { name: "upload", size: 16 }
                                        {t("settings.import")}
                                    }
                                }
                            }
                        }
                    }
                } else {
                    div { class: "dash-tiles",
                        button { class: "tile", onclick: move |_| go(Nav::All),
                            div { class: "tile-icon", Icon { name: "grid", size: 18 } }
                            div { class: "grow",
                                div { class: "num", "{items.len()}" }
                                div { class: "lbl", {t("home.items")} }
                            }
                        }
                        button { class: "tile", onclick: move |_| go(Nav::Favorites),
                            div { class: "tile-icon fav", Icon { name: "star", size: 18 } }
                            div { class: "grow",
                                div { class: "num", "{favorite_count}" }
                                div { class: "lbl", {t("nav.favorites")} }
                            }
                        }
                        div { class: "tile",
                            div { class: "tile-icon", Icon { name: "vault", size: 18 } }
                            div { class: "grow",
                                div { class: "num", "{vaults.len()}" }
                                div { class: "lbl", {t("nav.vaults")} }
                            }
                        }
                        button { class: "tile", onclick: move |_| go(Nav::Watchtower(None)),
                            div { class: "tile-icon", style: "background:{color}22;color:{color}", Icon { name: "shield", size: 18 } }
                            div { class: "grow",
                                div { class: "num", "{report.score}" }
                                div { class: "lbl", "{words}" }
                            }
                        }
                    }
                    div { class: "dash-cols",
                        div { class: "dash-col",
                            div { class: "section",
                                CardHead { title: t("nav.favorites"), target: (favorite_count > SHOWN).then_some(Nav::Favorites) }
                                if favorites.is_empty() {
                                    div { class: "card-empty", {t("home.no_favorites")} }
                                }
                                for item in favorites.into_iter().take(SHOWN) {
                                    ItemRow { key: "{item.id}", item: item.clone(), detail: item.subtitle.clone() }
                                }
                            }
                            div { class: "section",
                                CardHead { title: t("home.recent"), target: Some(Nav::All) }
                                for item in recent {
                                    ItemRow { key: "{item.id}", item: item.clone(), detail: item.subtitle.clone(), when: item.updated_at }
                                }
                            }
                        }
                        div { class: "dash-col",
                            div { class: "section",
                                CardHead { title: t("home.security"), target: Some(Nav::Watchtower(None)) }
                                div { class: "mini-score",
                                    svg { view_box: "0 0 64 64",
                                        circle { cx: "32", cy: "32", r: "26", fill: "none", stroke: "var(--border)", stroke_width: "7" }
                                        circle { cx: "32", cy: "32", r: "26", fill: "none", stroke: "{color}", stroke_width: "7", stroke_linecap: "round",
                                            stroke_dasharray: "{dash} {circumference}", transform: "rotate(-90 32 32)" }
                                        text { x: "32", y: "37", text_anchor: "middle", font_size: "15", font_weight: "800", fill: "currentColor", "{report.score}" }
                                    }
                                    div {
                                        div { style: "font-weight:700;font-size:17px;color:{color}", "{words}" }
                                        div { class: "small muted", "{report.items_checked} {t(\"wt.items_checked\")}" }
                                    }
                                }
                                for kind in [IssueKind::Breached, IssueKind::Weak, IssueKind::Reused] {
                                    {
                                        let n = report.count(kind);
                                        rsx! {
                                            div { key: "{kind.id()}", class: "dash-row", onclick: move |_| go(Nav::Watchtower(Some(kind))),
                                                span { class: either(n > 0, "danger-text", "ok-text"), Icon { name: either(n > 0, "alert", "check"), size: 18 } }
                                                span { class: "grow", {issue_title(kind)} }
                                                span { class: if n > 0 { "count danger-text" } else { "count muted" }, "{n}" }
                                            }
                                        }
                                    }
                                }
                                if !report.breach_check_done {
                                    div { class: "dash-row", onclick: move |_| go(Nav::Watchtower(None)),
                                        span { class: "muted", Icon { name: "shield", size: 18 } }
                                        span { class: "grow muted small", {t("home.breach_hint")} }
                                        Icon { name: "chevron-right", size: 16 }
                                    }
                                }
                            }
                            div { class: "section",
                                CardHead { title: t("nav.vaults") }
                                for v in vaults {
                                    {
                                        let target = Nav::Vault(v.id.clone());
                                        rsx! {
                                            div { key: "{v.id}", class: "dash-row", onclick: move |_| go(target.clone()),
                                                div { class: "vault-ico", Icon { name: vault_icon(&v.icon, v.is_shared()), size: 17 } }
                                                div { class: "grow",
                                                    div { class: "t", "{v.name}" }
                                                    if v.is_shared() {
                                                        div { class: "small muted", {t("home.shared")} }
                                                    }
                                                }
                                                span { class: "count muted", "{v.item_count}" }
                                            }
                                        }
                                    }
                                }
                            }
                            if !categories.is_empty() {
                                div { class: "section",
                                    CardHead { title: t("nav.categories") }
                                    div { class: "chips",
                                        for (c , n) in categories {
                                            button { key: "{c.id()}", class: "chip", onclick: move |_| go(Nav::Category(c)),
                                                Icon { name: category_icon(c), size: 14 }
                                                span { {category_name(c)} }
                                                span { class: "n", "{n}" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// A card's title, with "See all" when there is more to see.
#[component]
fn CardHead(title: String, #[props(default)] target: Option<Nav>) -> Element {
    rsx! {
        div { class: "card-head",
            div { class: "section-title", "{title}" }
            if let Some(target) = target {
                button { class: "link-btn", onclick: move |_| go(target.clone()),
                    {t("home.see_all")}
                    Icon { name: "chevron-right", size: 14 }
                }
            }
        }
    }
}

/// An item on the dashboard; opens it in the list of all items.
#[component]
fn ItemRow(item: ItemSummary, detail: String, #[props(default)] when: Option<i64>) -> Element {
    let id = item.id.clone();
    rsx! {
        div { class: "item-row", onclick: move |_| open_item(&id),
            ItemAvatar { category: item.category, title: item.title.clone(), icon: item.icon.clone(), size: 32 }
            div { class: "grow",
                div { class: "t", "{item.title}" }
                if !detail.is_empty() {
                    div { class: "s", "{detail}" }
                }
            }
            if let Some(ts) = when {
                span { class: "small muted", style: "white-space:nowrap", {relative_time(ts)} }
            }
        }
    }
}
