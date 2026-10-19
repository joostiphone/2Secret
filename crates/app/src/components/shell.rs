//! The unlocked main window: sidebar, item list and detail pane.

use dioxus::prelude::*;
use twosecret_core::item::Category;
use twosecret_core::session::ItemFilter;
use twosecret_core::util::now;

use crate::components::{
    dashboard::DashboardPage, generator::GeneratorPage, item_edit::ItemEditor, item_view::ItemView,
    settings::SettingsPage, watchtower::WatchtowerPage,
};
use crate::i18n::{category_name, t};
use crate::icons::{category_icon, either, vault_icon, AccountAvatar, Icon, ItemAvatar, Logo};
use crate::platform;
use crate::state::*;

/// Background duties while unlocked: auto-lock and periodic sync.
fn use_background_tasks() {
    use_future(|| async move {
        let mut last_sync = 0i64;
        loop {
            platform::sleep_ms(1000).await;
            if SESSION.peek().is_none() {
                continue;
            }
            let minutes = PREFS.peek().auto_lock_minutes as i64;
            if minutes > 0 && now() - *ACTIVITY.peek() > minutes * 60 && BUSY.peek().is_none() {
                lock();
                continue;
            }
            let status = SYNC.peek().clone();
            let due = status.requested || now() - last_sync > 90;
            if due && !status.running && !status.needs_reauth && BUSY.peek().is_none() && MODAL.peek().is_none() {
                last_sync = now();
                run_sync(false).await;
            }
        }
    });
}

/// "Time for a backup", now and then (Settings → Backup & export).
#[component]
pub fn BackupReminder() -> Element {
    let prefs = PREFS.read().clone();
    let has_items = SESSION.read().as_ref().is_some_and(|s| s.item_count() > 0);
    if crate::extension::ENABLED || !backup_due(&prefs, has_items) {
        return rsx! {};
    }
    let text = if prefs.last_backup_at > 0 {
        t("backup.reminder_since").replace("{date}", &platform::local_date(prefs.last_backup_at))
    } else {
        t("backup.reminder_never").to_string()
    };
    rsx! {
        div { class: "banner",
            Icon { name: "download", size: 18 }
            div { class: "grow",
                div { class: "t", {t("backup.reminder_title")} }
                div { class: "d", "{text}" }
            }
            div { class: "row",
                button { class: "btn small primary", onclick: move |_| *MODAL.write() = Some(Modal::Backup), {t("backup.make")} }
                button { class: "btn small ghost",
                    onclick: move |_| {
                        PREFS.write().backup_snoozed_at = now();
                        save_prefs();
                    },
                    {t("backup.later")}
                }
            }
        }
    }
}

#[component]
pub fn Shell() -> Element {
    use_background_tasks();
    use_hook(|| {
        // The first reminder comes a week after 2Secret is first used here.
        let fresh = { PREFS.peek().last_backup_at == 0 && PREFS.peek().backup_snoozed_at == 0 };
        if fresh {
            PREFS.write().backup_snoozed_at = now();
            save_prefs();
        }
        if crate::extension::ENABLED {
            spawn(async move {
                *TAB_URL.write() = crate::extension::tab_url().await;
            });
        }
    });
    let nav = NAV.read().clone();
    let pane = PANE();
    let page = nav.is_page();
    let class = |p: Pane| if pane == p { "" } else { "pane-hidden" };
    rsx! {
        div { class: if page { "shell pages" } else { "shell" },
            // Which pane is in front, for the medium layout in style.css.
            "data-pane": match pane {
                Pane::Nav => "nav",
                Pane::List => "list",
                Pane::Detail => "detail",
            },
            nav { class: "sidebar {class(Pane::Nav)}", Sidebar {} }
            if page {
                main { class: if pane == Pane::Nav { "detail-pane pane-hidden" } else { "detail-pane" },
                    match nav {
                        Nav::Home => rsx! { DashboardPage {} },
                        Nav::Generator => rsx! { GeneratorPage {} },
                        Nav::Settings => rsx! { SettingsPage {} },
                        Nav::Watchtower(kind) => rsx! { WatchtowerPage { kind } },
                        _ => rsx! {},
                    }
                }
            } else {
                section { class: "list-pane {class(Pane::List)}", ItemList {} }
                main { class: "detail-pane {class(Pane::Detail)}", DetailPane {} }
            }
        }
    }
}

pub fn go(nav: Nav) {
    *NAV.write() = nav;
    *SELECTED.write() = None;
    *EDITING.write() = None;
    *PANE.write() = Pane::List;
}

#[component]
fn NavButton(
    target: Nav,
    icon: &'static str,
    label: String,
    #[props(default)] count: Option<usize>,
    #[props(default)] badge: Option<usize>,
) -> Element {
    let active = *NAV.read() == target || matches!((&*NAV.read(), &target), (Nav::Watchtower(_), Nav::Watchtower(_)));
    rsx! {
        button { class: if active { "nav-item active" } else { "nav-item" },
            onclick: move |_| go(target.clone()),
            Icon { name: icon, size: 17 }
            span { class: "label", "{label}" }
            if let Some(b) = badge.filter(|b| *b > 0) {
                span { class: "badge", "{b}" }
            } else if let Some(c) = count {
                span { class: "count", "{c}" }
            }
        }
    }
}

/// The account at the top of the sidebar. In the apps a menu to switch to the
/// other profile or add one.
#[component]
fn ProfileHead(name: String, email: String, photo: Option<String>) -> Element {
    let mut open = use_signal(|| false);
    let list = if open() { profiles() } else { Vec::new() };
    let room = list.len() < MAX_PROFILES;
    rsx! {
        button { class: "who-btn", aria_label: t("profiles.title"), aria_expanded: open(),
            onclick: move |_| if MULTI_PROFILE { open.toggle() },
            AccountAvatar { name: name.clone(), photo, size: 34 }
            div { class: "who",
                div { class: "n", "{name}" }
                div { class: "e", "{email}" }
            }
            if MULTI_PROFILE {
                Icon { name: "chevron-down", size: 14 }
            }
        }
        if open() {
            div { class: "menu-backdrop", onclick: move |_| open.set(false) }
            div { class: "profile-menu", role: "menu",
                for p in list {
                    button { key: "{p.slot}", role: "menuitem",
                        class: either(p.active, "profile-item active", "profile-item"),
                        onclick: move |_| {
                            open.set(false);
                            switch_profile(p.slot);
                        },
                        AccountAvatar { name: p.name.clone(), photo: p.photo.clone(), size: 28 }
                        div { class: "who",
                            div { class: "n", "{p.name}" }
                            div { class: "e", "{p.email}" }
                        }
                        if p.active {
                            Icon { name: "check", size: 15 }
                        }
                    }
                }
                if room {
                    button { class: "profile-item", role: "menuitem",
                        onclick: move |_| {
                            open.set(false);
                            add_profile();
                        },
                        div { class: "add-icon", Icon { name: "plus", size: 15 } }
                        div { class: "who",
                            div { class: "n", {t("profiles.add")} }
                            div { class: "e", {t("profiles.add_desc")} }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn Sidebar() -> Element {
    let session = SESSION.read();
    let Some(s) = session.as_ref() else { return rsx! {} };
    let account = s.account().clone();
    let photo = s.avatar();
    let all = s.item_count();
    let favorites = s.list(&ItemFilter { favorites_only: true, ..Default::default() }).len();
    let trash = s.list(&ItemFilter { trashed: true, ..Default::default() }).len();
    let mut categories: Vec<(Category, usize)> = Category::ALL
        .iter()
        .map(|c| (*c, s.list(&ItemFilter { category: Some(*c), ..Default::default() }).len()))
        .filter(|(_, n)| *n > 0)
        .collect();
    categories.sort_by_key(|(c, _)| *c);
    let vaults = s.vaults();
    let tags = s.tags();
    let linked = s.server().is_some();
    let last_sync = s.server().and_then(|l| l.last_sync_at);
    let issues = {
        let breaches = BREACHES.read().clone().unwrap_or_default();
        twosecret_core::watchtower::analyze(s.all_items(), &breaches, None)
            .issues
            .iter()
            .filter(|i| {
                matches!(
                    i.kind,
                    twosecret_core::watchtower::IssueKind::Breached
                        | twosecret_core::watchtower::IssueKind::Weak
                        | twosecret_core::watchtower::IssueKind::Reused
                )
            })
            .map(|i| i.item_id.clone())
            .collect::<std::collections::HashSet<_>>()
            .len()
    };
    drop(session);

    let (dot, sync_text) = sync_summary(linked, last_sync);

    rsx! {
        div { class: "sidebar-head",
            ProfileHead { name: account.name.clone(), email: account.email.clone(), photo }
            button { class: "icon-btn", title: t("lock.lock_now"), onclick: move |_| lock(), Icon { name: "lock", size: 17 } }
        }
        div { class: "nav",
            NavButton { target: Nav::Home, icon: "home", label: t("nav.home") }
            NavButton { target: Nav::All, icon: "grid", label: t("nav.all"), count: all }
            NavButton { target: Nav::Favorites, icon: "star", label: t("nav.favorites"), count: favorites }
            NavButton { target: Nav::Watchtower(None), icon: "shield", label: t("nav.watchtower"), badge: issues }
            NavButton { target: Nav::Generator, icon: "zap", label: t("nav.generator") }
            if !categories.is_empty() {
                div { class: "nav-section", {t("nav.categories")} }
                for (c , n) in categories {
                    NavButton { key: "{c.id()}", target: Nav::Category(c), icon: category_icon(c), label: category_name(c), count: n }
                }
            }
            div { class: "nav-section",
                span { {t("nav.vaults")} }
                button { class: "icon-btn", title: t("vault.new"), onclick: move |_| *MODAL.write() = Some(Modal::NewVault),
                    Icon { name: "plus", size: 14 }
                }
            }
            for v in vaults {
                NavButton { key: "{v.id}", target: Nav::Vault(v.id.clone()), icon: vault_icon(&v.icon, v.is_shared()), label: v.name.clone(), count: v.item_count }
            }
            if !tags.is_empty() {
                div { class: "nav-section", {t("nav.tags")} }
                for (tag , n) in tags {
                    NavButton { key: "tag-{tag}", target: Nav::Tag(tag.clone()), icon: "tag", label: tag.clone(), count: n }
                }
            }
            div { class: "nav-section" }
            NavButton { target: Nav::Trash, icon: "trash", label: t("nav.trash"), count: trash }
            NavButton { target: Nav::Settings, icon: "settings", label: t("nav.settings") }
        }
        button { class: "sidebar-foot", style: "border:none;background:transparent;cursor:pointer;width:100%;text-align:left",
            title: t("sync.now"),
            onclick: move |_| {
                if linked {
                    if SYNC.peek().needs_reauth {
                        *MODAL.write() = Some(Modal::Reauth);
                    } else {
                        dioxus::core::spawn_forever(run_sync(true));
                    }
                } else {
                    go(Nav::Settings);
                }
            },
            span { class: "sync-dot {dot}" }
            span { class: "grow", "{sync_text}" }
            if linked {
                Icon { name: "refresh", size: 14 }
            }
        }
    }
}

/// The sync state as a dot class (`.sync-dot`) and a line of text.
pub fn sync_summary(linked: bool, last_sync: Option<i64>) -> (&'static str, String) {
    let sync = SYNC.read().clone();
    if !linked {
        ("off", t("sync.local").to_string())
    } else if sync.running {
        ("busy", t("sync.syncing").to_string())
    } else if sync.needs_reauth {
        ("err", t("sync.signed_out").to_string())
    } else if sync.error.is_some() {
        ("err", t("sync.error").to_string())
    } else {
        (
            "",
            match last_sync {
                Some(ts) => format!("{} {}", t("sync.synced"), relative_time(ts)),
                None => t("sync.never").to_string(),
            },
        )
    }
}

pub fn relative_time(ts: i64) -> String {
    let d = (now() - ts).max(0);
    if d < 60 {
        t("time.just_now").to_string()
    } else if d < 3600 {
        format!("{} {}", d / 60, t("time.min_ago"))
    } else if d < 86_400 {
        format!("{} {}", d / 3600, t("time.hours_ago"))
    } else {
        platform::local_date(ts)
    }
}

pub fn nav_title(nav: &Nav) -> String {
    match nav {
        Nav::Home => t("nav.home").into(),
        Nav::All => t("nav.all").into(),
        Nav::Favorites => t("nav.favorites").into(),
        Nav::Category(c) => category_name(*c),
        Nav::Vault(id) => SESSION.peek().as_ref().and_then(|s| s.vault(id)).map(|v| v.name).unwrap_or_default(),
        Nav::Tag(tag) => format!("#{tag}"),
        Nav::Trash => t("nav.trash").into(),
        Nav::Watchtower(_) => t("nav.watchtower").into(),
        Nav::Generator => t("nav.generator").into(),
        Nav::Settings => t("nav.settings").into(),
    }
}

fn filter_for(nav: &Nav, search: &str) -> ItemFilter {
    let mut f = ItemFilter { query: search.to_string(), ..Default::default() };
    match nav {
        Nav::Favorites => f.favorites_only = true,
        Nav::Category(c) => f.category = Some(*c),
        Nav::Vault(id) => f.vault_id = Some(id.clone()),
        Nav::Tag(tag) => f.tag = Some(tag.clone()),
        Nav::Trash => f.trashed = true,
        _ => {}
    }
    f
}

#[component]
fn ItemList() -> Element {
    let nav = NAV.read().clone();
    let search = SEARCH.read().clone();
    let selected = SELECTED.read().clone();
    let session = SESSION.read();
    let Some(s) = session.as_ref() else { return rsx! {} };
    let items = s.list(&filter_for(&nav, &search));
    let tab_url = TAB_URL.read().clone();
    let suggestions = match (&tab_url, &nav) {
        (Some(url), Nav::All) if search.is_empty() => s.items_for_url(url),
        _ => Vec::new(),
    };
    let suggest_host = tab_url.as_deref().and_then(twosecret_core::util::url_host).unwrap_or_default();
    let vault = match &nav {
        Nav::Vault(id) => s.vault(id),
        _ => None,
    };
    drop(session);
    let title = nav_title(&nav);
    let is_trash = nav == Nav::Trash;
    let can_add = vault.as_ref().is_none_or(|v| v.role.can_write()) && !is_trash;

    rsx! {
        div { class: "list-head",
            div { class: "title-row",
                button { class: "icon-btn mobile-only", onclick: move |_| *PANE.write() = Pane::Nav, Icon { name: "menu" } }
                h2 { "{title}" }
                if let Some(v) = vault.clone() {
                    if v.role.can_manage() {
                        button { class: "icon-btn", title: t("vault.share"),
                            onclick: move |_| *MODAL.write() = Some(Modal::ShareVault(v.id.clone())),
                            Icon { name: "share", size: 17 }
                        }
                    }
                }
                if let Some(v) = vault.clone() {
                    if v.role.can_manage() || v.is_owner {
                        button { class: "icon-btn", title: t("vault.edit"),
                            onclick: move |_| *MODAL.write() = Some(Modal::EditVault(v.id.clone())),
                            Icon { name: "edit", size: 16 }
                        }
                    }
                }
                if is_trash && !items.is_empty() {
                    button { class: "btn small danger",
                        onclick: move |_| {
                            if let Some(n) = mutate(|s| s.empty_trash(None)) {
                                toast(&format!("{n} {}", t("toast.deleted_items")));
                            }
                        },
                        {t("trash.empty")}
                    }
                }
                if can_add {
                    button { class: "btn primary small", title: t("item.new"),
                        onclick: move |_| *MODAL.write() = Some(Modal::NewItem),
                        Icon { name: "plus", size: 16 }
                        span { {t("item.new_short")} }
                    }
                }
            }
            crate::components::emergency::EmergencyBanner {}
            BackupReminder {}
            div { class: "search",
                Icon { name: "search", size: 16 }
                for k in [SEARCH_RESET()] {
                    input {
                        key: "{k}",
                        onmounted: move |e: MountedEvent| *SEARCH_EL.write() = Some(e.data()),
                        placeholder: t("list.search"),
                        initial_value: "{search}",
                        autocapitalize: "off",
                        spellcheck: "false",
                        oninput: move |e| *SEARCH.write() = e.value(),
                    }
                }
                if !search.is_empty() {
                    button { class: "icon-btn clear", onclick: move |_| clear_search(),
                        Icon { name: "x", size: 14 }
                    }
                }
            }
        }
        div { class: "items",
            if !suggestions.is_empty() {
                div { class: "nav-section", style: "color:var(--muted);padding:10px 12px 4px", "{t(\"ext.suggestions\")} {suggest_host}" }
                for item in suggestions {
                    {
                        let id = item.id.clone();
                        let fill_id = item.id.clone();
                        rsx! {
                            div { key: "s-{item.id}", class: "item-row",
                                onclick: move |_| {
                                    *SELECTED.write() = Some(id.clone());
                                    *EDITING.write() = None;
                                    *PANE.write() = Pane::Detail;
                                },
                                ItemAvatar { category: item.category, title: item.title.clone(), icon: item.icon.clone() }
                                div { class: "grow",
                                    div { class: "t", "{item.title}" }
                                    div { class: "s", "{item.subtitle}" }
                                }
                                button { class: "btn primary small",
                                    onclick: move |e| { e.stop_propagation(); fill_item(&fill_id); },
                                    {t("ext.fill")}
                                }
                            }
                        }
                    }
                }
                div { class: "nav-section", style: "color:var(--muted);padding:10px 12px 4px", {t("nav.all")} }
            }
            if items.is_empty() {
                div { class: "empty",
                    Icon { name: either(is_trash, "trash", "key"), size: 40 }
                    if !search.is_empty() {
                        p { {t("list.no_results")} }
                    } else if is_trash {
                        p { {t("list.trash_empty")} }
                    } else {
                        p { {t("list.empty")} }
                        if can_add {
                            button { class: "btn primary", onclick: move |_| *MODAL.write() = Some(Modal::NewItem),
                                Icon { name: "plus", size: 16 }
                                {t("item.new")}
                            }
                        }
                    }
                }
            }
            for item in items {
                {
                    let id = item.id.clone();
                    let is_sel = selected.as_deref() == Some(item.id.as_str());
                    rsx! {
                        div {
                            key: "{item.id}",
                            class: if is_sel { "item-row selected" } else { "item-row" },
                            onclick: move |_| {
                                *SELECTED.write() = Some(id.clone());
                                *EDITING.write() = None;
                                *PANE.write() = Pane::Detail;
                            },
                            ItemAvatar { category: item.category, title: item.title.clone(), icon: item.icon.clone() }
                            div { class: "grow",
                                div { class: "t", "{item.title}" }
                                div { class: "s", "{item.subtitle}" }
                            }
                            if item.favorite {
                                span { class: "fav", Icon { name: "star", size: 14 } }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn DetailPane() -> Element {
    let editing = EDITING.read().is_some();
    let selected = SELECTED.read().clone();
    if editing {
        return rsx! { ItemEditor {} };
    }
    match selected {
        Some(id) if SESSION.read().as_ref().is_some_and(|s| s.item(&id).is_some()) => rsx! { ItemView { id } },
        _ => rsx! {
            div { class: "empty", style: "margin:auto",
                div { class: "brand-logo large", Logo { size: 40 } }
                p { {t("detail.nothing_selected")} }
            }
        },
    }
}
