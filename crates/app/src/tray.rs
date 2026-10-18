//! Desktop: the 2Secret icon in the menu bar (macOS) or the system tray
//! (Windows, Linux). Its menu opens the window, locks the vault or quits
//! 2Secret; on Windows a click on the icon opens the window. While the icon
//! is there, closing the window hides it and 2Secret keeps running (and still
//! locks after the auto-lock time). *Settings → Appearance* removes the icon,
//! and closing the window quits again.
//!
//! The window also comes back when 2Secret is started again (`link_handler`
//! on Windows and Linux, the Dock on macOS) and when a setup link arrives
//! (`code_setup`).

use dioxus::desktop::window;

#[cfg(not(target_os = "macos"))]
static SHOW: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// From any thread (`link_handler`): bring the window to the front.
#[cfg(not(target_os = "macos"))]
pub fn request_show() {
    SHOW.notify_one();
}

/// Show the window in front, also when it is hidden or minimized.
pub fn show() {
    let window = window();
    window.set_visible(true);
    window.set_minimized(false);
    window.set_focus();
}

/// Remove the icon before 2Secret ends. Windows would otherwise show it until
/// the mouse passes over it.
pub fn remove() {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    icon::remove();
}

/// Whether the icon is there (closing the window then hides it).
fn shown() -> bool {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    {
        icon::shown()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Whether this desktop shows the icon.
pub fn supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *SUPPORTED.get_or_init(icon::shows_status_icons)
    }
    #[cfg(not(target_os = "linux"))]
    {
        cfg!(any(target_os = "windows", target_os = "macos"))
    }
}

/// In the app component: the icon and its menu, and showing the window.
pub fn use_tray() {
    #[cfg(not(target_os = "macos"))]
    dioxus::prelude::use_hook(|| {
        dioxus::prelude::spawn(async {
            loop {
                SHOW.notified().await;
                show();
            }
        })
    });
    dioxus::desktop::use_wry_event_handler(|event, _| {
        use dioxus::desktop::tao::event::{Event, WindowEvent};
        match event {
            // macOS: a click on the Dock icon while the window is hidden.
            Event::Reopen { .. } => show(),
            // Closing the window ends 2Secret without the icon, which the
            // Quick Access window would keep open.
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } if !shown() => crate::quick::close(),
            Event::LoopDestroyed => remove(),
            _ => {}
        }
    });
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    icon::use_icon();
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
mod icon {
    use std::cell::RefCell;

    use dioxus::desktop::trayicon::menu::{Menu, MenuId, MenuItem, PredefinedMenuItem};
    use dioxus::desktop::trayicon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
    use dioxus::desktop::{window, WindowCloseBehaviour};
    use dioxus::prelude::*;

    use crate::i18n::t;
    use crate::state::{lock, Phase, BUSY, PHASE, PREFS};

    const OPEN: &str = "tray-open";
    const QUICK: &str = "tray-quick";
    const LOCK: &str = "tray-lock";
    const QUIT: &str = "tray-quit";

    struct Tray {
        /// The icon leaves the menu bar when this is dropped.
        _icon: TrayIcon,
        open: MenuItem,
        quick: MenuItem,
        lock: MenuItem,
        quit: MenuItem,
    }

    thread_local! {
        /// The icon belongs to the main thread.
        static TRAY: RefCell<Option<Tray>> = const { RefCell::new(None) };
    }

    pub fn use_icon() {
        // Add, update or remove the icon. Not before the preferences are read.
        use_effect(|| {
            let phase = PHASE.read().clone();
            if phase == Phase::Loading {
                return;
            }
            let wanted = PREFS.read().tray && super::supported();
            let texts = [t("tray.open"), t("tray.quick"), t("tray.lock"), t("tray.quit")];
            let shown = TRAY.with_borrow_mut(|tray| {
                if !wanted {
                    *tray = None;
                } else if tray.is_none() {
                    *tray = create();
                }
                if let Some(tray) = tray {
                    for (item, text) in [&tray.open, &tray.quick, &tray.lock, &tray.quit].into_iter().zip(texts) {
                        item.set_text(text);
                    }
                    tray.lock.set_enabled(phase == Phase::Unlocked);
                }
                tray.is_some()
            });
            window().set_close_behavior(if shown {
                WindowCloseBehaviour::WindowHides
            } else {
                WindowCloseBehaviour::WindowCloses
            });
        });
        // Menu events come as either kind, depending on which Dioxus set up last.
        dioxus::desktop::use_tray_menu_event_handler(|event| choose(event.id()));
        dioxus::desktop::use_muda_event_handler(|event| choose(event.id()));
        // Windows: a click opens the window, the menu is under the right mouse
        // button.
        dioxus::desktop::use_tray_icon_event_handler(|event| {
            if cfg!(target_os = "windows")
                && matches!(
                    event,
                    TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. }
                )
            {
                super::show();
            }
        });
    }

    pub fn remove() {
        TRAY.with_borrow_mut(|tray| *tray = None);
    }

    pub fn shown() -> bool {
        TRAY.with_borrow(|tray| tray.is_some())
    }

    fn choose(id: &MenuId) {
        match id.0.as_str() {
            OPEN => super::show(),
            QUICK => crate::quick::request(),
            LOCK if *PHASE.peek() == Phase::Unlocked && BUSY.peek().is_none() => lock(),
            QUIT => quit(),
            _ => {}
        }
    }

    /// Close the window for real, which ends the app.
    fn quit() {
        crate::quick::close();
        let window = window();
        window.set_close_behavior(WindowCloseBehaviour::WindowCloses);
        window.close();
    }

    fn create() -> Option<Tray> {
        let open = MenuItem::with_id(OPEN, t("tray.open"), true, None);
        // The shortcut shows next to it (it works without the menu too).
        let quick = MenuItem::with_id(QUICK, t("tray.quick"), true, "CmdOrCtrl+Shift+Space".parse().ok());
        let lock = MenuItem::with_id(LOCK, t("tray.lock"), false, None);
        let quit = MenuItem::with_id(QUIT, t("tray.quit"), true, None);
        let menu = Menu::new();
        menu.append_items(&[&open, &quick, &lock, &PredefinedMenuItem::separator(), &quit]).ok()?;
        // Linux: the name panels show for the icon (else the program's name).
        // GLib warns when it is set twice.
        #[cfg(target_os = "linux")]
        {
            static NAMED: std::sync::Once = std::sync::Once::new();
            NAMED.call_once(|| gio::glib::set_application_name("2Secret"));
        }
        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_icon(image()?)
            .with_icon_as_template(cfg!(target_os = "macos"))
            .with_menu_on_left_click(!cfg!(target_os = "windows"))
            .with_tooltip("2Secret")
            .build()
            .ok()?;
        Some(Tray { _icon: icon, open, quick, lock, quit })
    }

    /// macOS: a black template image, which the menu bar colours like its
    /// other icons. Windows and Linux: the app icon.
    fn image() -> Option<Icon> {
        #[cfg(target_os = "macos")]
        let png: &[u8] = include_bytes!("../assets/tray-template.png");
        #[cfg(target_os = "windows")]
        let png: &[u8] = include_bytes!("../assets/icon-32.png");
        #[cfg(target_os = "linux")]
        let png: &[u8] = include_bytes!("../assets/icon-64.png");
        let image = image::load_from_memory_with_format(png, image::ImageFormat::Png).ok()?.into_rgba8();
        let (width, height) = image.dimensions();
        Icon::from_rgba(image.into_raw(), width, height).ok()
    }

    /// Linux shows the icon through AppIndicator. Its library is loaded at run
    /// time (the tray icon crate panics without it), and the panel has to show
    /// such icons: GNOME only does with the AppIndicator extension.
    #[cfg(target_os = "linux")]
    pub fn shows_status_icons() -> bool {
        let library = ["libayatana-appindicator3.so.1", "libappindicator3.so.1"]
            .into_iter()
            // Stays loaded for the tray icon crate, which loads it again.
            .any(|name| unsafe { libloading::Library::new(name) }.map(std::mem::forget).is_ok());
        library && status_notifier_watcher()
    }

    /// Whether a panel collects status icons (StatusNotifierItem).
    #[cfg(target_os = "linux")]
    fn status_notifier_watcher() -> bool {
        use gio::glib::ToVariant;
        let Ok(bus) = gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE) else {
            return false;
        };
        bus.call_sync(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameHasOwner",
            Some(&("org.kde.StatusNotifierWatcher",).to_variant()),
            None,
            gio::DBusCallFlags::NONE,
            1000,
            gio::Cancellable::NONE,
        )
        .ok()
        .and_then(|reply| reply.get::<(bool,)>())
        .is_some_and(|(owned,)| owned)
    }
}
