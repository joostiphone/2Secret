//! 2Secret – one Rust UI for macOS, Windows, Linux, the BSDs, iOS, Android
//! and the web. `src/main.rs` starts it; the iOS App Store build links this
//! library into an Xcode project and calls [`twosecret_main`].

#[cfg(feature = "desktop")]
mod agent_access;
#[cfg(target_os = "android")]
mod android;
#[cfg(any(target_os = "ios", target_os = "macos"))]
mod apple_autofill;
#[cfg(feature = "desktop")]
mod autostart;
mod avatar;
mod biometric;
mod code_setup;
mod components;
mod extension;
mod i18n;
mod icons;
#[cfg(all(target_os = "ios", feature = "mobile"))]
mod ios_view;
#[cfg(all(feature = "desktop", not(target_os = "macos")))]
mod link_handler;
mod platform;
#[cfg(feature = "desktop")]
mod quick;
#[cfg(feature = "desktop")]
mod screen_qr;
#[cfg(feature = "desktop")]
mod ssh_agent;
mod state;
#[cfg(feature = "desktop")]
mod tray;
mod updater;

use dioxus::prelude::*;

#[cfg(feature = "desktop")]
use agent_access::AgentPrompt;
use components::actions::ContextMenu;
use components::modals::ModalHost;
use components::onboarding::{CreateAccount, LockScreen, NewAccount, SignIn, Welcome};
use components::passkey::PasskeyPrompt;
use components::shell::Shell;
use components::widgets::{BusyOverlay, ToastHost};
#[cfg(feature = "desktop")]
use quick::QuickShortcut;
#[cfg(feature = "desktop")]
use ssh_agent::SshPrompt;
/// Only the desktop has Agent Access.
#[cfg(not(feature = "desktop"))]
#[component]
fn AgentPrompt() -> Element {
    rsx! {}
}
/// Only the desktop has Quick Access.
#[cfg(not(feature = "desktop"))]
#[component]
fn QuickShortcut() -> Element {
    rsx! {}
}
/// Only the desktop has the SSH agent.
#[cfg(not(feature = "desktop"))]
#[component]
fn SshPrompt() -> Element {
    rsx! {}
}
use state::*;

pub(crate) const STYLE: &str = include_str!("style.css");

/// Desktop windows: Dioxus applies UI updates in the next animation frame,
/// and waits until they are applied before it runs the app further. Hidden
/// windows draw no frames, so a window hidden in the menu bar or system tray
/// (or the hidden Quick Access window) would stop 2Secret at its next update,
/// until it shows again. This applies updates right away while the window is
/// hidden, and after a moment when no frame comes.
#[cfg(feature = "desktop")]
pub(crate) const HIDDEN_UPDATES_JS: &str = r#"<script>
(function () {
  var current;
  Object.defineProperty(window, "interpreter", {
    configurable: true,
    get: function () { return current; },
    set: function (interpreter) {
      current = interpreter;
      if (!interpreter || typeof interpreter.rafEdits !== "function") return;
      interpreter.rafEdits = function (bytes) {
        var self = this;
        self.enqueueBytes(bytes);
        var flush = function () {
          if (self.queuedBytes.length) {
            self.flushQueuedBytes();
            self.markEditsFinished();
          }
        };
        if (document.hidden) { flush(); return; }
        requestAnimationFrame(flush);
        setTimeout(flush, 250);
      };
    }
  });
})();
</script>"#;

/// Start the app (does not return).
pub fn run() {
    // Windows, Linux, BSDs: a setup link that started another 2Secret goes to
    // the one that runs.
    #[cfg(all(feature = "desktop", not(target_os = "macos")))]
    link_handler::start();
    // A downloaded update is installed before the app starts (and restarts it).
    updater::apply_at_start();
    #[cfg(feature = "desktop")]
    {
        use dioxus::desktop::{Config, LogicalSize, WindowBuilder};
        // Started at login: only the icon in the menu bar or system tray.
        let hidden = autostart::started_hidden() && state::stored_prefs().tray && tray::supported();
        std::thread::spawn(autostart::refresh);
        let window = WindowBuilder::new()
            .with_title("2Secret")
            .with_inner_size(LogicalSize::new(1200.0, 780.0))
            .with_min_inner_size(LogicalSize::new(360.0, 520.0))
            .with_visible(!hidden);
        let mut config = Config::new()
            .with_window(window)
            // `tray` decides what a click on the icon does.
            .with_tray_icon_show_window_on_click(false)
            .with_background_color((244, 245, 248, 255))
            .with_data_directory(platform::data_dir().join("webview"))
            .with_custom_head(format!(
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><style>{STYLE}</style>{HIDDEN_UPDATES_JS}"
            ));
        // Window and taskbar icon (macOS uses the app bundle's icon instead).
        if let Ok(icon) = dioxus::desktop::icon_from_memory(include_bytes!("../assets/icon-256.png")) {
            config = config.with_icon(icon);
        }
        config = config.with_custom_event_handler(|event, _| {
            if let dioxus::desktop::tao::event::Event::Opened { urls } = event {
                code_setup::opened(urls.iter().map(|u| u.as_str()));
            }
        });
        dioxus::LaunchBuilder::desktop().with_cfg(config).launch(App);
    }
    #[cfg(feature = "mobile")]
    {
        // maximum-scale: iOS zooms in on a text field with small text when it
        // gets the focus, and an app does not zoom.
        let config = dioxus::mobile::Config::new()
            .with_custom_head(
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover\">"
                    .to_string(),
            )
            .with_custom_event_handler(|event, _| {
                if let dioxus::mobile::tao::event::Event::Opened { urls } = event {
                    code_setup::opened(urls.iter().map(|u| u.as_str()));
                }
            });
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
    // Escape closes a menu, then a dialog, then stops picking items.
    if e.key() == Key::Escape {
        if MENU.peek().is_some() {
            *MENU.write() = None;
            return;
        }
        if MODAL.peek().is_some() {
            *MODAL.write() = None;
            return;
        }
        if PICKED.peek().is_some() {
            *PICKED.write() = None;
            return;
        }
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
            components::shell::open_search();
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

/// The tab bar on phones (`TabBar` in shell.rs). iOS only shows a pressed
/// button (`:active`) on a page that listens to touches. And it only opens
/// the keyboard for a field that gets the focus during the tap, while the
/// search field may only appear once Rust has handled the tap: a stand-in
/// field takes the focus now and hands it on when the search field is there.
#[cfg(feature = "mobile")]
const TAB_BAR_JS: &str = r#"
(function () {
  if (window.twosecretTabBar) return;
  window.twosecretTabBar = true;
  document.addEventListener("touchstart", function () {}, { passive: true });
  document.addEventListener("click", function (e) {
    var proxy = document.getElementById("search-proxy");
    if (!proxy || !e.target.closest || !e.target.closest("[data-search]")) return;
    proxy.focus();
    var frames = 0;
    (function handOn() {
      var field = document.querySelector(".list-pane:not(.pane-hidden) .search input");
      if (field) field.focus();
      else if (++frames < 60) requestAnimationFrame(handOn);
      else proxy.blur();
    })();
  }, true);
})();
"#;

/// Phones and tablets: a long press on an item or a vault (`data-menu`)
/// opens its menu, as a right click does on a computer; iOS sends no
/// `contextmenu` event for a long press. Android does: the first of the two
/// counts. The tap that ends a long press, however long the finger stays,
/// does not also open the item or close the menu, and moving the finger
/// (scrolling) is no long press.
#[cfg(feature = "mobile")]
const LONG_PRESS_JS: &str = r#"
(function () {
  if (window.twosecretLongPress) return;
  window.twosecretLongPress = true;
  var timer = null, start = null, longPress = false, releasedAt = 0;
  function cancel() { clearTimeout(timer); timer = null; }
  function release() {
    cancel();
    if (longPress) { longPress = false; releasedAt = Date.now(); }
  }
  document.addEventListener("touchstart", function (e) {
    // A new touch: the click of the last one has come (or not) by now.
    cancel();
    longPress = false;
    releasedAt = 0;
    var el = e.target.closest && e.target.closest("[data-menu]");
    if (!el || e.touches.length !== 1) return;
    start = { x: e.touches[0].clientX, y: e.touches[0].clientY };
    timer = setTimeout(function () {
      timer = null;
      longPress = true;
      if (navigator.vibrate) navigator.vibrate(10);
      el.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true, clientX: start.x, clientY: start.y }));
    }, 450);
  }, { passive: true });
  document.addEventListener("touchmove", function (e) {
    if (!timer) return;
    var t = e.touches[0];
    if (Math.abs(t.clientX - start.x) > 10 || Math.abs(t.clientY - start.y) > 10) cancel();
  }, { passive: true });
  document.addEventListener("touchend", release, { passive: true });
  document.addEventListener("touchcancel", release, { passive: true });
  document.addEventListener("contextmenu", function (e) {
    if (!e.isTrusted) return;
    if (timer) { cancel(); longPress = true; return; }
    if (longPress) { e.preventDefault(); e.stopImmediatePropagation(); }
  }, true);
  // iOS goes on with its own long press under the finger, which by then
  // rests on the menu: it selects no text there.
  document.addEventListener("selectstart", function (e) {
    if (longPress || Date.now() - releasedAt < 600) e.preventDefault();
  }, true);
  document.addEventListener("click", function (e) {
    if (longPress || Date.now() - releasedAt < 600) {
      e.preventDefault();
      e.stopImmediatePropagation();
      releasedAt = 0;
    }
  }, true);
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
        spawn(code_setup::receive());
    });
    #[cfg(feature = "desktop")]
    tray::use_tray();
    #[cfg(feature = "desktop")]
    quick::use_quick_access();
    #[cfg(feature = "desktop")]
    ssh_agent::use_ssh_agent();
    #[cfg(feature = "desktop")]
    agent_access::use_agent_access();
    // The shortcut needs the preferences.
    #[cfg(feature = "desktop")]
    let quick_shortcut = PREFS.read().quick_access && *PHASE.read() != Phase::Loading;
    #[cfg(not(feature = "desktop"))]
    let quick_shortcut = false;
    // A one-time password from an otpauth:// link, once the vault is unlocked
    // and no other dialog is open.
    use_effect(|| {
        if *PHASE.read() == Phase::Unlocked && MODAL.read().is_none() && CODE_SETUP.read().is_some() {
            let uri = CODE_SETUP.write().take();
            *MODAL.write() = uri.map(Modal::SetUpCode);
        }
    });
    #[cfg(feature = "mobile")]
    use_effect(|| {
        let _ = dioxus::document::eval(KEYBOARD_JS);
        let _ = dioxus::document::eval(TAB_BAR_JS);
        let _ = dioxus::document::eval(LONG_PRESS_JS);
    });
    #[cfg(all(target_os = "ios", feature = "mobile"))]
    use_hook(ios_view::hide_scroll_edges);
    #[cfg(all(target_os = "ios", feature = "mobile"))]
    use_effect(|| ios_view::follow_theme(PREFS.read().theme.id()));
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
            ContextMenu {}
            ModalHost {}
            BusyOverlay {}
            ToastHost {}
            if quick_shortcut {
                QuickShortcut {}
            }
            SshPrompt {}
            AgentPrompt {}
        }
    }
}
