//! Desktop: the menu bar. Dioxus's own menu, with "Check for Updates…": in
//! the app menu on macOS (the first menu, which macOS names after the app),
//! in a Help menu on Windows and Linux. It works before signing in and while
//! locked, so an update that fixes signing in can still be found.

use dioxus::desktop::muda::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use dioxus::prelude::*;

use crate::i18n::{t_in, Lang};
use crate::state::{Modal, MODAL};
use crate::{platform, state, updater};

const CHECK_UPDATES: &str = "2secret-check-updates";

/// The menu bar, in the language of the preferences (or the system's).
pub fn menu_bar() -> Menu {
    let lang = state::stored_prefs().lang.unwrap_or_else(|| Lang::from_code(&platform::system_language()));
    let updates = (updater::mode() != updater::Mode::Off)
        .then(|| MenuItem::with_id(CHECK_UPDATES, t_in(lang, "menu.check_updates"), true, None));

    let menu = Menu::new();
    let window_menu = Submenu::new("Window", true);
    if cfg!(target_os = "macos") {
        if let Some(item) = &updates {
            let _ = window_menu.append_items(&[item, &PredefinedMenuItem::separator()]);
        }
    }
    let _ = window_menu.append_items(&[
        &PredefinedMenuItem::fullscreen(None),
        &PredefinedMenuItem::separator(),
        &PredefinedMenuItem::hide(None),
        &PredefinedMenuItem::hide_others(None),
        &PredefinedMenuItem::show_all(None),
        &PredefinedMenuItem::maximize(None),
        &PredefinedMenuItem::minimize(None),
        &PredefinedMenuItem::close_window(None),
        &PredefinedMenuItem::separator(),
        &PredefinedMenuItem::quit(None),
    ]);

    let edit_menu = Submenu::new("Edit", true);
    let _ = edit_menu.append_items(&[
        &PredefinedMenuItem::undo(None),
        &PredefinedMenuItem::redo(None),
        &PredefinedMenuItem::separator(),
        &PredefinedMenuItem::cut(None),
        &PredefinedMenuItem::copy(None),
        &PredefinedMenuItem::paste(None),
        &PredefinedMenuItem::separator(),
        &PredefinedMenuItem::select_all(None),
    ]);
    let _ = menu.append_items(&[&window_menu, &edit_menu]);

    if !cfg!(target_os = "macos") {
        if let Some(item) = &updates {
            let help_menu = Submenu::new(t_in(lang, "menu.help"), true);
            let _ = help_menu.append(item);
            let _ = menu.append(&help_menu);
        }
    }

    #[cfg(target_os = "macos")]
    window_menu.set_as_windows_menu_for_nsapp();

    menu
}

/// Answer the menu's own items.
pub fn use_app_menu() {
    // Menu events come as either kind, depending on which Dioxus set up last
    // (see `tray`); the same item may be answered twice, which is harmless.
    dioxus::desktop::use_muda_event_handler(|event| chosen(event.id().as_ref()));
    dioxus::desktop::use_tray_menu_event_handler(|event| chosen(event.id().as_ref()));
}

fn chosen(id: &str) {
    if id != CHECK_UPDATES {
        return;
    }
    *MODAL.write() = Some(Modal::Updates);
    let busy = matches!(
        *updater::STATUS.peek(),
        updater::Status::Checking | updater::Status::Downloading { .. } | updater::Status::Ready { .. }
    );
    if !busy {
        dioxus::core::spawn_forever(updater::check(false));
    }
}
