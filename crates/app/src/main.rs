//! 2Secret – one Rust UI for macOS, Windows, Linux, the BSDs, iOS and the web.

mod components;
mod extension;
mod i18n;
mod icons;
mod platform;
mod state;

use dioxus::prelude::*;

use components::modals::ModalHost;
use components::onboarding::{CreateAccount, LockScreen, NewAccount, SignIn, Welcome};
use components::shell::Shell;
use components::widgets::{BusyOverlay, ToastHost};
use state::*;

const STYLE: &str = include_str!("style.css");

fn main() {
    #[cfg(feature = "desktop")]
    {
        use dioxus::desktop::{Config, LogicalSize, WindowBuilder};
        let window = WindowBuilder::new()
            .with_title("2Secret")
            .with_inner_size(LogicalSize::new(1200.0, 780.0))
            .with_min_inner_size(LogicalSize::new(360.0, 520.0));
        let config = Config::new()
            .with_window(window)
            .with_background_color((244, 245, 248, 255))
            .with_data_directory(platform::data_dir().join("webview"))
            .with_custom_head(format!(
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><style>{STYLE}</style>"
            ));
        dioxus::LaunchBuilder::desktop().with_cfg(config).launch(App);
    }
    #[cfg(feature = "mobile")]
    {
        let config = dioxus::mobile::Config::new().with_custom_head(
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">".to_string(),
        );
        dioxus::LaunchBuilder::mobile().with_cfg(config).launch(App);
    }
    #[cfg(not(any(feature = "desktop", feature = "mobile")))]
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    use_hook(init);
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
            class: if extension::ENABLED { "root ext" } else { "root" },
            "data-theme": theme,
            onclick: move |_| touch(),
            onkeydown: move |_| touch(),
            match phase {
                Phase::Loading => rsx! {},
                Phase::Welcome => rsx! { Welcome {} },
                Phase::Create => rsx! { CreateAccount {} },
                Phase::SignIn => rsx! { SignIn {} },
                Phase::NewAccount { secret_key } => rsx! { NewAccount { secret_key } },
                Phase::Locked => rsx! { LockScreen {} },
                Phase::Unlocked => rsx! { Shell {} },
            }
            ModalHost {}
            BusyOverlay {}
            ToastHost {}
        }
    }
}
