//! 2Secret – one Rust UI for macOS, Windows, Linux, the BSDs, iOS, Android
//! and the web. `src/main.rs` starts it; the iOS App Store build links this
//! library into an Xcode project and calls [`twosecret_main`].

#[cfg(target_os = "android")]
mod android;
#[cfg(any(target_os = "ios", target_os = "macos"))]
mod apple_autofill;
mod avatar;
mod biometric;
mod components;
mod extension;
mod i18n;
mod icons;
mod platform;
mod state;
mod updater;

use dioxus::prelude::*;

use components::modals::ModalHost;
use components::onboarding::{CreateAccount, LockScreen, NewAccount, SignIn, Welcome};
use components::passkey::PasskeyPrompt;
use components::shell::Shell;
use components::widgets::{BusyOverlay, ToastHost};
use state::*;

const STYLE: &str = include_str!("style.css");

/// Start the app (does not return).
pub fn run() {
    // A downloaded update is installed before the app starts (and restarts it).
    updater::apply_at_start();
    #[cfg(feature = "desktop")]
    {
        use dioxus::desktop::{Config, LogicalSize, WindowBuilder};
        let window = WindowBuilder::new()
            .with_title("2Secret")
            .with_inner_size(LogicalSize::new(1200.0, 780.0))
            .with_min_inner_size(LogicalSize::new(360.0, 520.0));
        let mut config = Config::new()
            .with_window(window)
            .with_background_color((244, 245, 248, 255))
            .with_data_directory(platform::data_dir().join("webview"))
            .with_custom_head(format!(
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><style>{STYLE}</style>"
            ));
        // Window and taskbar icon (macOS uses the app bundle's icon instead).
        if let Ok(icon) = dioxus::desktop::icon_from_memory(include_bytes!("../assets/icon-256.png")) {
            config = config.with_icon(icon);
        }
        dioxus::LaunchBuilder::desktop().with_cfg(config).launch(App);
    }
    #[cfg(feature = "mobile")]
    {
        // maximum-scale: iOS zooms in on a text field with small text when it
        // gets the focus, and an app does not zoom.
        let config = dioxus::mobile::Config::new().with_custom_head(
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover\">"
                .to_string(),
        );
        dioxus::LaunchBuilder::mobile().with_cfg(config).launch(App);
    }
    #[cfg(not(any(feature = "desktop", feature = "mobile")))]
    dioxus::launch(App);
}

/// Entry point for the iOS app built with Xcode (see `ios/`).
#[cfg(target_os = "ios")]
#[no_mangle]
pub extern "C" fn twosecret_main() {
    run();
}

/// Keyboard shortcuts: Ctrl/Cmd+L lock, Ctrl/Cmd+N new item, Ctrl/Cmd+F search,
/// Escape closes dialogs.
fn shortcut(e: KeyboardEvent) {
    let m = e.modifiers();
    if e.key() == Key::Escape && MODAL.peek().is_some() {
        *MODAL.write() = None;
        return;
    }
    if !(m.ctrl() || m.meta()) || *PHASE.peek() != Phase::Unlocked || BUSY.peek().is_some() {
        return;
    }
    let Key::Character(c) = e.key() else { return };
    match c.to_lowercase().as_str() {
        "l" => {
            e.prevent_default();
            lock();
        }
        "n" if EDITING.peek().is_none() => {
            e.prevent_default();
            *MODAL.write() = Some(Modal::NewItem);
        }
        "f" => {
            e.prevent_default();
            if NAV.peek().is_page() {
                *NAV.write() = Nav::All;
            }
            *PANE.write() = Pane::List;
            let el = SEARCH_EL.peek().clone();
            if let Some(el) = el {
                spawn(async move {
                    let _ = el.set_focus(true).await;
                });
            }
        }
        _ => {}
    }
}

/// Phones and tablets: iOS keeps a text field above the keyboard by scrolling
/// the whole page, and does not always scroll it back, for instance when the
/// field disappears because the vault unlocked. The app was then shifted up
/// under the status bar. The page itself never scrolls (panes inside it do),
/// so this keeps it at the top and fits the app into the visible part of the
/// screen, above the keyboard (`.kb` in style.css).
#[cfg(feature = "mobile")]
const KEYBOARD_JS: &str = r#"
(function () {
  var vv = window.visualViewport;
  if (!vv || window.twosecretKeyboard) return;
  window.twosecretKeyboard = true;
  var html = document.documentElement;
  var queued = false, wanted = false;
  function field() {
    var a = document.activeElement;
    var typing = !!a && (a.tagName === "INPUT" || a.tagName === "TEXTAREA" || a.tagName === "SELECT" || a.isContentEditable);
    return typing ? a : null;
  }
  // Scroll the pane around the field (not the page) so the field shows.
  function reveal(el) {
    for (var p = el.parentElement; p && p !== document.body; p = p.parentElement) {
      var o = getComputedStyle(p).overflowY;
      if ((o === "auto" || o === "scroll") && p.scrollHeight > p.clientHeight) {
        var a = el.getBoundingClientRect(), b = p.getBoundingClientRect();
        if (a.bottom > b.bottom) p.scrollTop += a.bottom - b.bottom + 12;
        else if (a.top < b.top) p.scrollTop -= b.top - a.top + 12;
        return;
      }
    }
  }
  function fit() {
    var show = wanted;
    queued = false;
    wanted = false;
    if (window.scrollX || window.scrollY) window.scrollTo(0, 0);
    var top = Math.max(0, Math.round(vv.offsetTop));
    html.style.setProperty("--app-height", Math.round(vv.height) + "px");
    html.style.setProperty("--app-top", top + "px");
    html.classList.toggle("kb-open", vv.height < window.innerHeight - 80);
    html.classList.toggle("kb-shift", top > 0);
    var el = field();
    if (show && el) reveal(el);
  }
  function later(show) {
    wanted = wanted || show;
    if (queued) return;
    queued = true;
    requestAnimationFrame(fit);
  }
  html.classList.add("kb");
  fit();
  vv.addEventListener("resize", function () { later(true); });
  vv.addEventListener("scroll", function () { later(false); });
  window.addEventListener("scroll", function () { later(false); }, { passive: true });
  document.addEventListener("focusout", function () { setTimeout(function () { later(false); }, 50); });
})();
"#;

#[component]
fn App() -> Element {
    use_hook(|| {
        spawn(async move {
            platform::prepare().await;
            init();
        });
        spawn(updater::background());
    });
    #[cfg(feature = "mobile")]
    use_effect(|| {
        let _ = dioxus::document::eval(KEYBOARD_JS);
    });
    let theme = PREFS.read().theme.id();
    let phase = PHASE.read().clone();
    rsx! {
        // Title and viewport come from index.html (web) or the window /
        // webview configuration (desktop, mobile). `document::Title` would
        // need `eval`, which the web vault's Content Security Policy forbids.
        if !cfg!(feature = "desktop") {
            style { dangerous_inner_html: STYLE }
        }
        div {
            class: match (extension::ENABLED, PASSKEY.read().is_some()) {
                (true, true) => "root ext window",
                (true, false) => "root ext",
                _ => "root",
            },
            "data-theme": theme,
            onclick: move |_| touch(),
            onkeydown: move |e: KeyboardEvent| {
                touch();
                shortcut(e);
            },
            match phase {
                Phase::Loading => rsx! {},
                Phase::Welcome => rsx! { Welcome {} },
                Phase::Create => rsx! { CreateAccount {} },
                Phase::SignIn => rsx! { SignIn {} },
                Phase::NewAccount { secret_key } => rsx! { NewAccount { secret_key } },
                // A new lock screen for each profile.
                Phase::Locked => rsx! { LockScreen { key: "{SLOT()}" } },
                Phase::Unlocked if PASSKEY.read().is_some() => rsx! { PasskeyPrompt {} },
                Phase::Unlocked => rsx! { Shell {} },
            }
            ModalHost {}
            BusyOverlay {}
            ToastHost {}
        }
    }
}
