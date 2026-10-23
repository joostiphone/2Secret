//! Desktop: Quick Access. A shortcut (Ctrl+Shift+Space, ⇧⌘Space on the Mac)
//! opens a small window anywhere to find an item and copy its password, user
//! name or one-time code, without the 2Secret window. `2-secret
//! --quick-access` does the same while 2Secret runs, for a shortcut set in
//! the desktop's own settings (under Wayland apps cannot register one).
//!
//! The window is a second webview with its own UI ([`QuickWindow`]). It gets
//! a list of the items without their secrets and asks the main window, which
//! holds the unlocked vault, to copy one. It is hidden after use and closed
//! when the vault locks.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Mutex;

use dioxus::desktop::{Config, DesktopContext, LogicalSize, WindowBuilder};
use dioxus::prelude::*;
use tokio::sync::Notify;
use twosecret_core::item::ItemSummary;
use twosecret_core::totp::Totp;

use crate::i18n::{t, Lang, LANG};
use crate::icons::{Icon, ItemAvatar};
use crate::state::*;

/// Opens Quick Access in the 2Secret that runs (`link_handler`).
pub const ARG: &str = "--quick-access";
const SHORTCUT: &str = "CmdOrCtrl+Shift+Space";

/// The shortcut as people read it.
pub fn shortcut_label() -> String {
    if cfg!(target_os = "macos") {
        format!("⇧⌘{}", t("quick.space"))
    } else {
        format!("Ctrl+Shift+{}", t("quick.space"))
    }
}

/// An item as Quick Access shows it: no secrets.
#[derive(Clone, PartialEq)]
struct Entry {
    summary: ItemSummary,
    username: bool,
    password: bool,
    code: bool,
}

struct Snapshot {
    entries: Vec<Entry>,
    lang: Lang,
    theme: &'static str,
}

#[derive(Clone, Copy, PartialEq)]
enum What {
    Password,
    Username,
    Code,
    /// Show the item in the 2Secret window.
    Open,
}

/// For the Quick Access window, from the main window.
static SNAPSHOT: Mutex<Option<Snapshot>> = Mutex::new(None);
/// The Quick Access window shows a new snapshot.
static REFRESH: Notify = Notify::const_new();
/// Open Quick Access (shortcut, `link_handler`).
static OPEN: Notify = Notify::const_new();
/// Copy requests of the Quick Access window, for the main window.
static ACTIONS: Mutex<Vec<(String, What)>> = Mutex::new(Vec::new());
static ACTION: Notify = Notify::const_new();

thread_local! {
    /// Asked while the vault was locked: open once it is unlocked.
    static PENDING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    // Both windows run on the main thread.
    static WINDOW: RefCell<Option<DesktopContext>> = const { RefCell::new(None) };
    static MAIN: RefCell<Option<DesktopContext>> = const { RefCell::new(None) };
}

/// From any thread: open Quick Access.
pub fn request() {
    OPEN.notify_one();
}

/// Close the window (when the vault locks, or 2Secret quits).
pub fn close() {
    *SNAPSHOT.lock().unwrap_or_else(|e| e.into_inner()) = None;
    if let Some(window) = WINDOW.with_borrow_mut(Option::take) {
        window.close();
    }
}

/// In the app component: the shortcut, and the main window's side.
pub fn use_quick_access() {
    use_hook(|| {
        MAIN.set(Some(dioxus::desktop::window()));
        spawn(async {
            loop {
                OPEN.notified().await;
                open();
            }
        });
        spawn(async {
            loop {
                ACTION.notified().await;
                let actions = std::mem::take(&mut *ACTIONS.lock().unwrap_or_else(|e| e.into_inner()));
                for (id, what) in actions {
                    perform(&id, what);
                }
            }
        });
    });
    // Nothing of the vault stays in the window once it locks.
    use_effect(|| {
        if *PHASE.read() != Phase::Unlocked {
            close();
        } else if PENDING.replace(false) {
            open();
        }
    });
}

/// Registers the shortcut while it is mounted (*Settings → Desktop app*).
#[component]
pub fn QuickShortcut() -> Element {
    let registered = dioxus::desktop::use_global_shortcut(SHORTCUT, |state| {
        if state == dioxus::desktop::HotKeyState::Pressed {
            request();
        }
    });
    let ok = registered.is_ok();
    use_effect(move || *SHORTCUT_TAKEN.write() = !ok);
    use_drop(|| *SHORTCUT_TAKEN.write() = false);
    rsx! {}
}

/// Another app has the shortcut.
pub static SHORTCUT_TAKEN: GlobalSignal<bool> = Signal::global(|| false);

fn entries() -> Vec<Entry> {
    let session = SESSION.peek();
    let Some(session) = session.as_ref() else { return Vec::new() };
    session
        .all_items()
        .filter(|(_, item)| !item.is_trashed())
        .map(|(vault, item)| Entry {
            summary: item.summary(vault),
            username: item.username().is_some(),
            password: item.password().is_some(),
            code: item.totp_secret().is_some(),
        })
        .collect()
}

fn open() {
    if *PHASE.peek() != Phase::Unlocked {
        // Unlock first.
        PENDING.set(true);
        crate::tray::show();
        return;
    }
    let shown = WINDOW.with_borrow(|w| w.as_ref().map(|w| w.is_visible() && w.is_focused()));
    if shown == Some(true) {
        dismiss();
        return;
    }
    let snapshot = Snapshot { entries: entries(), lang: *LANG.peek(), theme: PREFS.peek().theme.id() };
    *SNAPSHOT.lock().unwrap_or_else(|e| e.into_inner()) = Some(snapshot);
    let existing = WINDOW.with_borrow(|w| w.clone());
    match existing {
        Some(window) => {
            REFRESH.notify_one();
            if let Some(position) = position() {
                window.set_outer_position(position);
            }
            window.set_visible(true);
            window.set_focus();
        }
        None => create(),
    }
}

const WIDTH: f64 = 620.0;
const HEIGHT: f64 = 420.0;

/// Centred on the screen with the mouse pointer, a bit above the middle.
fn position() -> Option<dioxus::desktop::tao::dpi::PhysicalPosition<i32>> {
    let main = MAIN.with_borrow(|m| m.clone())?;
    let monitor = main
        .cursor_position()
        .ok()
        .and_then(|p| main.monitor_from_point(p.x, p.y))
        .or_else(|| main.current_monitor())
        .or_else(|| main.primary_monitor())?;
    let (origin, size, scale) = (monitor.position(), monitor.size(), monitor.scale_factor());
    let x = origin.x as f64 + (size.width as f64 - WIDTH * scale) / 2.0;
    let y = origin.y as f64 + size.height as f64 * 0.2;
    Some(dioxus::desktop::tao::dpi::PhysicalPosition::new(x as i32, y as i32))
}

fn create() {
    let Some(main) = MAIN.with_borrow(|m| m.clone()) else { return };
    let mut window = WindowBuilder::new()
        .with_title("2Secret")
        .with_inner_size(LogicalSize::new(WIDTH, HEIGHT))
        .with_decorations(false)
        .with_resizable(false)
        .with_always_on_top(true);
    if let Some(position) = position() {
        window = window.with_position(position);
    }
    #[cfg(windows)]
    {
        use dioxus::desktop::tao::platform::windows::WindowBuilderExtWindows;
        window = window.with_skip_taskbar(true);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use dioxus::desktop::tao::platform::unix::WindowBuilderExtUnix;
        window = window.with_skip_taskbar(true);
    }
    let config = Config::new()
        .with_window(window)
        .with_background_color((244, 245, 248, 255))
        .with_data_directory(crate::platform::data_dir().join("webview"))
        .with_custom_head(format!("<style>{}</style>{}", crate::STYLE, crate::HIDDEN_UPDATES_JS));
    let pending = main.new_window(VirtualDom::new(QuickWindow), config);
    spawn(async move {
        let window = pending.resolve().await;
        WINDOW.set(Some(window));
    });
}

/// Hide Quick Access, and give the keyboard back to the app that had it.
fn dismiss() {
    let Some(window) = WINDOW.with_borrow(|w| w.clone()) else { return };
    window.set_visible(false);
    #[cfg(target_os = "macos")]
    if !MAIN.with_borrow(|m| m.as_ref().is_some_and(|m| m.is_visible())) {
        // The app that was active before comes back to the front.
        unsafe {
            let app: *mut objc2::runtime::AnyObject = objc2::msg_send![objc2::class!(NSApplication), sharedApplication];
            let nil: *mut objc2::runtime::AnyObject = std::ptr::null_mut();
            let _: () = objc2::msg_send![app, hide: nil];
        }
    }
}

fn perform(id: &str, what: What) {
    touch();
    if what == What::Open {
        open_item(id);
        crate::tray::show();
        return;
    }
    let found = {
        let session = SESSION.peek();
        let Some(item) = session.as_ref().and_then(|s| s.item(id)) else { return };
        match what {
            What::Password => item.password().map(|p| (p.to_string(), t("field.password"))),
            What::Username => item.username().map(|u| (u.to_string(), t("field.username"))),
            What::Code => {
                item.totp_secret().and_then(|s| Totp::parse(s).ok()).map(|totp| (totp.now().0, t("field.totp")))
            }
            What::Open => None,
        }
    };
    if let Some((value, label)) = found {
        copy(value, label);
    }
}

/// How well an item fits the search; `None`: not at all.
fn rank(entry: &Entry, query: &str) -> Option<u8> {
    let s = &entry.summary;
    if query.is_empty() {
        return Some(0);
    }
    let title = s.title.to_lowercase();
    if title.starts_with(query) {
        return Some(0);
    }
    if title.split(|c: char| !c.is_alphanumeric()).any(|word| word.starts_with(query)) {
        return Some(1);
    }
    if title.contains(query) {
        return Some(2);
    }
    let elsewhere = s.host.as_deref().is_some_and(|h| h.to_lowercase().contains(query))
        || s.url.as_deref().is_some_and(|u| u.to_lowercase().contains(query))
        || s.subtitle.to_lowercase().contains(query)
        || s.tags.iter().any(|tag| tag.to_lowercase().contains(query));
    elsewhere.then_some(3)
}

fn results(entries: &[Entry], query: &str) -> Vec<Entry> {
    let query = query.trim().to_lowercase();
    let mut found: Vec<(u8, &Entry)> = entries.iter().filter_map(|e| Some((rank(e, &query)?, e))).collect();
    // Favorites first, as in the item list.
    found.sort_by(|(ra, a), (rb, b)| {
        b.summary
            .favorite
            .cmp(&a.summary.favorite)
            .then(ra.cmp(rb))
            .then(a.summary.title.to_lowercase().cmp(&b.summary.title.to_lowercase()))
    });
    found.into_iter().take(50).map(|(_, e)| e.clone()).collect()
}

/// The Quick Access window (its own virtual DOM).
#[component]
fn QuickWindow() -> Element {
    let mut entries = use_signal(Vec::<Entry>::new);
    let mut theme = use_signal(|| "system");
    let mut query = use_signal(String::new);
    let mut selected = use_signal(|| 0usize);
    let mut field = use_signal(|| None::<Rc<MountedData>>);
    let mut done = use_signal(|| None::<&'static str>);
    let mut had_focus = use_signal(|| false);
    // Focus moves around while the window shows: losing it then does not
    // hide the window.
    let mut shown_at = use_signal(std::time::Instant::now);
    // Where the mouse pointer was: only moving it selects a row, not a row
    // that appears under a pointer that stands still.
    let mut pointer = use_signal(|| None::<(f64, f64)>);

    let mut load = move || {
        let Some(snapshot) = SNAPSHOT.lock().unwrap_or_else(|e| e.into_inner()).take() else { return };
        *LANG.write() = snapshot.lang;
        theme.set(snapshot.theme);
        entries.set(snapshot.entries);
        query.set(String::new());
        selected.set(0);
        done.set(None);
        had_focus.set(false);
        shown_at.set(std::time::Instant::now());
        pointer.set(None);
    };
    // The search field gets the keyboard whenever the window does (it was
    // hidden, or is new).
    let focus_field = move || {
        spawn(async move {
            // Once the window shows (focusing it before can fail).
            crate::platform::sleep_ms(30).await;
            let window = dioxus::desktop::window();
            window.set_focus();
            let _ = window.webview.focus();
            if let Some(el) = field() {
                let _ = el.set_focus(true).await;
            }
        });
    };
    use_hook(move || {
        load();
        spawn(async move {
            loop {
                REFRESH.notified().await;
                load();
                focus_field();
            }
        })
    });
    // Away when another window gets the keyboard.
    dioxus::desktop::use_wry_event_handler(move |event, _| {
        use dioxus::desktop::tao::event::{Event, WindowEvent};
        if let Event::WindowEvent { event: WindowEvent::Focused(focused), .. } = event {
            if *focused {
                had_focus.set(true);
                focus_field();
            } else if had_focus() && done().is_none() && shown_at().elapsed().as_millis() > 500 {
                dismiss();
            }
        }
    });

    let found = results(&entries.read(), &query.read());
    let count = found.len();
    let current = selected().min(count.saturating_sub(1));
    use_effect(move || {
        selected();
        let _ = document::eval("document.querySelector('.quick-row.selected')?.scrollIntoView({block: 'nearest'})");
    });

    let mut act = move |entry: &Entry, what: What| {
        let what = match what {
            What::Password if !entry.password => What::Open,
            What::Username if !entry.username => return,
            What::Code if !entry.code => return,
            other => other,
        };
        ACTIONS.lock().unwrap_or_else(|e| e.into_inner()).push((entry.summary.id.clone(), what));
        ACTION.notify_one();
        let message = match what {
            What::Password => t("quick.copied_password"),
            What::Username => t("quick.copied_username"),
            What::Code => t("quick.copied_code"),
            What::Open => {
                dismiss();
                return;
            }
        };
        done.set(Some(message));
        spawn(async move {
            crate::platform::sleep_ms(500).await;
            dismiss();
        });
    };

    let keys = found.clone();
    let onkeydown = move |e: KeyboardEvent| match e.key() {
        Key::ArrowDown => {
            e.prevent_default();
            selected.set((current + 1).min(count.saturating_sub(1)));
        }
        Key::ArrowUp => {
            e.prevent_default();
            selected.set(current.saturating_sub(1));
        }
        Key::Enter => {
            e.prevent_default();
            let Some(entry) = keys.get(current) else { return };
            let m = e.modifiers();
            let what = if m.shift() {
                What::Username
            } else if m.ctrl() || m.meta() {
                What::Code
            } else if m.alt() {
                What::Open
            } else {
                What::Password
            };
            act(entry, what);
        }
        Key::Escape => dismiss(),
        _ => {}
    };
    let modifier = if cfg!(target_os = "macos") { "⌘" } else { "Ctrl" };
    let alt = if cfg!(target_os = "macos") { "⌥" } else { "Alt" };

    rsx! {
        div { class: "root quick", "data-theme": theme(),
            div { class: "quick-search",
                Icon { name: "search", size: 20 }
                input {
                    value: "{query}",
                    placeholder: t("quick.placeholder"),
                    autocomplete: "off",
                    spellcheck: "false",
                    autocapitalize: "off",
                    onmounted: move |e: MountedEvent| async move {
                        let el = e.data();
                        field.set(Some(el.clone()));
                        let _ = el.set_focus(true).await;
                    },
                    oninput: move |e| {
                        query.set(e.value());
                        selected.set(0);
                    },
                    onkeydown,
                }
            }
            if let Some(message) = done() {
                div { class: "quick-done", Icon { name: "check", size: 22 } "{message}" }
            } else if found.is_empty() {
                div { class: "quick-empty", {t("quick.nothing")} }
            } else {
                div { class: "quick-list",
                    for (i , entry) in found.into_iter().enumerate() {
                        div {
                            key: "{entry.summary.id}",
                            class: if i == current { "quick-row selected" } else { "quick-row" },
                            onmousemove: move |e: MouseEvent| {
                                let at = e.client_coordinates();
                                let at = (at.x, at.y);
                                if pointer().is_some_and(|before| before != at) {
                                    selected.set(i);
                                }
                                pointer.set(Some(at));
                            },
                            onclick: {
                                let entry = entry.clone();
                                move |_| act(&entry, What::Password)
                            },
                            ItemAvatar { category: entry.summary.category, title: entry.summary.title.clone(), size: 32, icon: entry.summary.icon.clone() }
                            div { class: "grow",
                                div { class: "t", "{entry.summary.title}" }
                                div { class: "s", "{entry.summary.subtitle}" }
                            }
                            if i == current {
                                div { class: "quick-actions",
                                    for (what , available , label) in [
                                        (What::Username, entry.username, t("quick.username")),
                                        (What::Password, entry.password, t("quick.password")),
                                        (What::Code, entry.code, t("quick.code")),
                                    ] {
                                        if available {
                                            button {
                                                class: "quick-chip",
                                                onclick: {
                                                    let entry = entry.clone();
                                                    move |e: MouseEvent| {
                                                        e.stop_propagation();
                                                        act(&entry, what);
                                                    }
                                                },
                                                "{label}"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            div { class: "quick-foot",
                span { kbd { "↵" } " " {t("quick.password")} }
                span { kbd { "⇧↵" } " " {t("quick.username")} }
                span { kbd { "{modifier}↵" } " " {t("quick.code")} }
                span { kbd { "{alt}↵" } " " {t("quick.open")} }
                span { class: "grow" }
                span { kbd { "Esc" } }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twosecret_core::item::Item;

    fn entry(title: &str, url: &str, favorite: bool) -> Entry {
        let mut item = Item::login(title, "me", "pw", Some(url));
        item.favorite = favorite;
        Entry { summary: item.summary("v"), username: true, password: true, code: false }
    }

    #[test]
    fn search_ranks_favorites_then_titles() {
        let entries = vec![
            entry("My Bank", "https://bank.example", false),
            entry("Banking app", "https://other.example", false),
            entry("Mail", "https://bankmail.example", false),
            entry("Shop", "https://shop.example", true),
            entry("Savings", "https://bank.example/savings", true),
        ];
        let titles = |q: &str| results(&entries, q).into_iter().map(|e| e.summary.title).collect::<Vec<_>>();
        assert_eq!(titles("bank"), ["Savings", "Banking app", "My Bank", "Mail"]);
        assert_eq!(titles("BANKING"), ["Banking app"]);
        // No search: favourites first.
        assert_eq!(titles("")[..2], ["Savings", "Shop"]);
        assert!(titles("nothing like this").is_empty());
    }
}
