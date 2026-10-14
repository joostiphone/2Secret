//! Small reusable UI building blocks.

use dioxus::prelude::*;
use twosecret_core::generator::GeneratorOptions;
use twosecret_core::strength::{estimate, StrengthLevel};
use twosecret_core::totp::Totp;

use crate::i18n::t;
use crate::icons::{either, Icon, Logo};
use crate::platform;
use crate::state::*;

#[component]
pub fn ToastHost() -> Element {
    let toast = TOAST.read().clone();
    rsx! {
        if let Some(toast) = toast {
            div { key: "{toast.id}", class: if toast.error { "toast error" } else { "toast" },
                Icon { name: either(toast.error, "alert", "check"), size: 16 }
                span { "{toast.text}" }
            }
        }
    }
}

#[component]
pub fn BusyOverlay() -> Element {
    let busy = BUSY.read().clone();
    rsx! {
        if let Some(text) = busy {
            div { class: "busy",
                div { class: "busy-card",
                    div { class: "spinner" }
                    span { "{text}" }
                }
            }
        }
    }
}

/// A modal dialog frame.
#[component]
pub fn ModalFrame(title: String, children: Element, #[props(default)] footer: Option<Element>) -> Element {
    rsx! {
        div { class: "modal-backdrop",
            onclick: move |_| *MODAL.write() = None,
            div { class: "modal", onclick: move |e| e.stop_propagation(),
                div { class: "modal-head",
                    h3 { "{title}" }
                    button { class: "icon-btn", title: t("common.close"), onclick: move |_| *MODAL.write() = None,
                        Icon { name: "x" }
                    }
                }
                div { class: "modal-body", {children} }
                if let Some(footer) = footer {
                    div { class: "modal-foot", {footer} }
                }
            }
        }
    }
}

/// A password shown with coloured digits and symbols (like 1Password).
#[component]
pub fn ColoredPassword(value: String) -> Element {
    rsx! {
        span { class: "mono",
            for (i , c) in value.chars().enumerate() {
                if c.is_ascii_digit() {
                    span { key: "{i}", class: "pw-digit", "{c}" }
                } else if c.is_alphabetic() {
                    span { key: "{i}", "{c}" }
                } else {
                    span { key: "{i}", class: "pw-symbol", "{c}" }
                }
            }
        }
    }
}

pub fn level_label(level: StrengthLevel) -> &'static str {
    match level {
        StrengthLevel::Terrible => t("strength.terrible"),
        StrengthLevel::Weak => t("strength.weak"),
        StrengthLevel::Fair => t("strength.fair"),
        StrengthLevel::Good => t("strength.good"),
        StrengthLevel::Fantastic => t("strength.fantastic"),
    }
}

/// Strength bar with label for a password.
#[component]
pub fn StrengthMeter(password: String, #[props(default)] inputs: Vec<String>) -> Element {
    if password.is_empty() {
        return rsx! {};
    }
    let refs: Vec<&str> = inputs.iter().map(|s| s.as_str()).collect();
    let s = estimate(&password, &refs);
    let score = s.level.score();
    let width = (score as u32 + 1) * 20;
    let label = level_label(s.level);
    rsx! {
        div {
            div { class: "meter", div { class: "s{score}", style: "width:{width}%" } }
            div { class: "row small muted", style: "margin-top:5px",
                span { "{label}" }
                span { class: "spacer" }
                span { "{s.bits:.0} bits" }
            }
            if let Some(w) = s.warning {
                div { class: "small warn-text", style: "margin-top:3px", "{w}" }
            }
        }
    }
}

/// Focus an element as soon as it is mounted (more reliable than the
/// `autofocus` attribute for dynamically inserted elements).
pub async fn focus_on_mount(e: MountedEvent) {
    let _ = e.set_focus(true).await;
}

/// Password input with reveal toggle and optional generator button.
///
/// The input is *uncontrolled* (`initial_value`): with controlled inputs fast
/// typing can lose keystrokes in webviews. Programmatic changes (generated
/// passwords, `reset`) re-create the element instead.
#[component]
pub fn PasswordInput(
    value: String,
    oninput: EventHandler<String>,
    #[props(default)] placeholder: String,
    #[props(default)] generate: bool,
    #[props(default)] autofocus: bool,
    #[props(default)] onenter: Option<EventHandler<()>>,
    /// Change this to clear/replace the field from outside.
    #[props(default)]
    reset: u32,
) -> Element {
    let mut reveal = use_signal(|| false);
    let mut version = use_signal(|| 0u32);
    let kind = if reveal() { "text" } else { "password" };
    let key = format!("{reset}-{}", version());
    rsx! {
        div { class: "input-group",
            for k in [key] {
                input {
                    key: "{k}",
                    class: "input mono",
                    r#type: kind,
                    initial_value: "{value}",
                    placeholder: "{placeholder}",
                    autofocus: autofocus,
                    onmounted: move |e: MountedEvent| async move {
                        if autofocus {
                            let _ = e.set_focus(true).await;
                        }
                    },
                    autocomplete: "off",
                    spellcheck: "false",
                    autocapitalize: "off",
                    oninput: move |e| oninput.call(e.value()),
                    onkeydown: move |e| {
                        if e.key() == Key::Enter {
                            if let Some(h) = onenter {
                                h.call(());
                            }
                        }
                    },
                }
            }
            if generate {
                button { class: "icon-btn", r#type: "button", title: t("gen.generate"),
                    onclick: move |_| {
                        let opts = PREFS.peek().generator.clone();
                        let opts = if opts.kind == twosecret_core::generator::GeneratorKind::Pin {
                            GeneratorOptions::random(20)
                        } else {
                            opts
                        };
                        oninput.call(opts.generate());
                        version += 1;
                        reveal.set(true);
                    },
                    Icon { name: "zap", size: 16 }
                }
            }
            button { class: "icon-btn", r#type: "button", title: t("common.reveal"),
                onclick: move |_| reveal.toggle(),
                Icon { name: either(reveal(), "eye-off", "eye"), size: 16 }
            }
        }
    }
}

/// A live TOTP code with a countdown ring.
#[component]
pub fn TotpCode(secret: String) -> Element {
    let mut tick = use_signal(twosecret_core::util::now);
    use_future(move || async move {
        loop {
            platform::sleep_ms(1000).await;
            tick.set(twosecret_core::util::now());
        }
    });
    let totp = match Totp::parse(&secret) {
        Ok(t) => t,
        Err(_) => return rsx! { span { class: "danger-text", {t("item.invalid_totp")} } },
    };
    let ts = tick();
    let code = totp.code_at(ts);
    let left = totp.seconds_remaining(ts);
    let frac = left as f64 / totp.period as f64;
    let dash = 2.0 * std::f64::consts::PI * 9.0;
    let offset = dash * (1.0 - frac);
    let color = if left <= 5 { "var(--danger)" } else { "var(--accent)" };
    let shown = Totp::format_code(&code);
    rsx! {
        div { class: "totp",
            span { "{shown}" }
            svg { class: "totp-ring", view_box: "0 0 22 22",
                circle { cx: "11", cy: "11", r: "9", fill: "none", stroke: "var(--border)", stroke_width: "3" }
                circle { cx: "11", cy: "11", r: "9", fill: "none", stroke: "{color}", stroke_width: "3",
                    stroke_dasharray: "{dash}", stroke_dashoffset: "{offset}", transform: "rotate(-90 11 11)" }
            }
            span { class: "small muted", "{left}s" }
            button { class: "icon-btn", title: t("common.copy"), onclick: move |_| copy(code.clone(), t("field.totp")),
                Icon { name: "copy", size: 16 }
            }
        }
    }
}

/// Language selector links (onboarding screens).
#[component]
pub fn LangSwitch() -> Element {
    let current = crate::i18n::LANG();
    rsx! {
        div { class: "lang-switch",
            for lang in crate::i18n::Lang::ALL {
                button {
                    key: "{lang.code()}",
                    class: if lang == current { "on" } else { "" },
                    onclick: move |_| set_lang(lang),
                    "{lang.name()}"
                }
            }
        }
    }
}

/// The 2Secret logo + name block.
#[component]
pub fn Brand(#[props(default)] subtitle: String) -> Element {
    rsx! {
        div { class: "brand",
            div { class: "brand-logo", Logo { size: 28 } }
            div {
                h1 { "2Secret" }
                if !subtitle.is_empty() {
                    p { "{subtitle}" }
                }
            }
        }
    }
}

/// Where an account syncs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ServerChoice {
    /// The 2Secret server (`twosecret_client::OFFICIAL_SERVER`).
    Official,
    /// A server of the user's own.
    Custom,
    /// No server: only on this device.
    Local,
}

/// Whether the apps offer the 2Secret server (`sync.2secret.app`). When off,
/// only a web vault served by it offers it.
const OFFICIAL_SERVER_LIVE: bool = true;

fn is_official(url: &str) -> bool {
    twosecret_client::normalize_server_url(url) == twosecret_client::OFFICIAL_SERVER
}

impl ServerChoice {
    fn official_offered() -> bool {
        OFFICIAL_SERVER_LIVE || platform::default_server().is_some_and(|url| is_official(&url))
    }

    /// What to start with: the server this web vault comes from, else the
    /// 2Secret server when it is offered, else only on this device (when
    /// `allow_local`) or an own server. The custom address is pre-filled
    /// with the web vault's server.
    pub fn initial(allow_local: bool) -> (ServerChoice, String) {
        match platform::default_server() {
            Some(url) if is_official(&url) => (ServerChoice::Official, String::new()),
            Some(url) => (ServerChoice::Custom, url),
            None if OFFICIAL_SERVER_LIVE => (ServerChoice::Official, String::new()),
            None if allow_local => (ServerChoice::Local, String::new()),
            None => (ServerChoice::Custom, String::new()),
        }
    }

    /// The server address, or `None` for only on this device.
    pub fn url(self, custom: &str) -> Option<String> {
        match self {
            ServerChoice::Official => Some(twosecret_client::OFFICIAL_SERVER.to_string()),
            ServerChoice::Custom => Some(custom.trim().to_string()),
            ServerChoice::Local => None,
        }
    }
}

/// The 2Secret server, an own server or (when `allow_local`) none.
#[component]
pub fn ServerPicker(
    choice: Signal<ServerChoice>,
    custom: Signal<String>,
    #[props(default)] allow_local: bool,
) -> Element {
    let mut options = Vec::new();
    if ServerChoice::official_offered() {
        options.push((ServerChoice::Official, "cloud", t("server.official"), t("server.official_desc")));
    }
    options.push((ServerChoice::Custom, "server", t("server.custom"), t("server.custom_desc")));
    if allow_local {
        options.push((ServerChoice::Local, "smartphone", t("server.local"), t("server.local_desc")));
    }
    // With an own server as the only option, just ask for its address.
    let single = options.len() == 1;
    rsx! {
        div { class: "form-group",
            for (option , icon , title , desc) in options.into_iter().filter(|_| !single) {
                button { key: "{title}", r#type: "button",
                    class: if choice() == option { "choice compact on" } else { "choice compact" },
                    onclick: move |_| choice.set(option),
                    Icon { name: icon, size: 20 }
                    div {
                        div { class: "t", "{title}" }
                        div { class: "d", "{desc}" }
                    }
                }
            }
            if choice() == ServerChoice::Custom {
                input { class: "input", initial_value: "{custom}", placeholder: "https://vault.example.com", autocapitalize: "off",
                    oninput: move |e| custom.set(e.value()) }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_without_the_2secret_server_until_it_runs() {
        assert!(!OFFICIAL_SERVER_LIVE || ServerChoice::official_offered());
        let (create, _) = ServerChoice::initial(true);
        let (sign_in, _) = ServerChoice::initial(false);
        if OFFICIAL_SERVER_LIVE {
            assert_eq!((create, sign_in), (ServerChoice::Official, ServerChoice::Official));
        } else {
            assert!(!ServerChoice::official_offered());
            assert_eq!((create, sign_in), (ServerChoice::Local, ServerChoice::Custom));
        }
    }
}
