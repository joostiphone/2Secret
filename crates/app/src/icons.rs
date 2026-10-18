//! Inline SVG icons (paths from the MIT licensed Feather icon set).

use dioxus::prelude::*;
use twosecret_core::Category;

fn path(name: &str) -> &'static str {
    match name {
        "lock" => r#"<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>"#,
        "key" => {
            r#"<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>"#
        }
        "star" => {
            r#"<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>"#
        }
        "search" => r#"<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>"#,
        "plus" => r#"<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>"#,
        "copy" => {
            r#"<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>"#
        }
        "eye" => r#"<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>"#,
        "eye-off" => {
            r#"<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>"#
        }
        "trash" => {
            r#"<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>"#
        }
        "edit" => r#"<path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/>"#,
        "refresh" => {
            r#"<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>"#
        }
        "shield" => r#"<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>"#,
        "settings" => {
            r#"<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/>"#
        }
        "vault" => {
            r#"<polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/>"#
        }
        "grid" => {
            r#"<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>"#
        }
        "home" => {
            r#"<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>"#
        }
        "user" => r#"<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>"#,
        "users" => {
            r#"<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>"#
        }
        "credit-card" => {
            r#"<rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line x1="1" y1="10" x2="23" y2="10"/>"#
        }
        "note" => {
            r#"<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>"#
        }
        "globe" => {
            r#"<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>"#
        }
        "wifi" => {
            r#"<path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>"#
        }
        "server" => {
            r#"<rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>"#
        }
        "database" => {
            r#"<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>"#
        }
        "terminal" => r#"<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>"#,
        "mail" => {
            r#"<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>"#
        }
        "book" => {
            r#"<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>"#
        }
        "award" => r#"<circle cx="12" cy="8" r="7"/><polyline points="8.21 13.89 7 23 12 20 17 23 15.79 13.88"/>"#,
        "gift" => {
            r#"<polyline points="20 12 20 22 4 22 4 12"/><rect x="2" y="7" width="20" height="5"/><line x1="12" y1="22" x2="12" y2="7"/><path d="M12 7H7.5a2.5 2.5 0 0 1 0-5C11 2 12 7 12 7z"/><path d="M12 7h4.5a2.5 2.5 0 0 0 0-5C13 2 12 7 12 7z"/>"#
        }
        "bank" => {
            r#"<line x1="3" y1="22" x2="21" y2="22"/><line x1="6" y1="18" x2="6" y2="11"/><line x1="10" y1="18" x2="10" y2="11"/><line x1="14" y1="18" x2="14" y2="11"/><line x1="18" y1="18" x2="18" y2="11"/><polygon points="12 2 20 7 4 7"/>"#
        }
        "hexagon" => {
            r#"<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>"#
        }
        "package" => {
            r#"<line x1="16.5" y1="9.4" x2="7.5" y2="4.21"/><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>"#
        }
        "code" => r#"<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>"#,
        "paperclip" => {
            r#"<path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>"#
        }
        "truck" => {
            r#"<rect x="1" y="3" width="15" height="13"/><polygon points="16 8 20 8 23 11 23 16 16 16 16 8"/><circle cx="5.5" cy="18.5" r="2.5"/><circle cx="18.5" cy="18.5" r="2.5"/>"#
        }
        "x" => r#"<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>"#,
        "check" => r#"<polyline points="20 6 9 17 4 12"/>"#,
        "chevron-left" => r#"<polyline points="15 18 9 12 15 6"/>"#,
        "chevron-down" => r#"<polyline points="6 9 12 15 18 9"/>"#,
        "chevron-right" => r#"<polyline points="9 18 15 12 9 6"/>"#,
        "more" => r#"<circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/>"#,
        "share" => {
            r#"<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>"#
        }
        "download" => {
            r#"<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>"#
        }
        "upload" => {
            r#"<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>"#
        }
        "clock" => r#"<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>"#,
        "alert" => {
            r#"<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>"#
        }
        "tag" => {
            r#"<path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/>"#
        }
        "menu" => {
            r#"<line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/>"#
        }
        "external" => {
            r#"<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>"#
        }
        "cloud" => r#"<path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>"#,
        "cloud-off" => {
            r#"<path d="M22.61 16.95A5 5 0 0 0 18 10h-1.26a8 8 0 0 0-7.05-6M5 5a8 8 0 0 0 4 15h9a5 5 0 0 0 1.7-.3"/><line x1="1" y1="1" x2="23" y2="23"/>"#
        }
        "zap" => r#"<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>"#,
        "logout" => {
            r#"<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>"#
        }
        "restore" => r#"<polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>"#,
        "folder" => r#"<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>"#,
        "smartphone" => {
            r#"<rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/>"#
        }
        "qr-code" => {
            r#"<rect width="5" height="5" x="3" y="3" rx="1"/><rect width="5" height="5" x="16" y="3" rx="1"/><rect width="5" height="5" x="3" y="16" rx="1"/><path d="M21 16h-3a2 2 0 0 0-2 2v3"/><path d="M21 21v.01"/><path d="M12 7v3a2 2 0 0 1-2 2H7"/><path d="M3 12h.01"/><path d="M12 3h.01"/><path d="M12 16v.01"/><path d="M16 12h1"/><path d="M21 12v.01"/><path d="M12 21v-1"/>"#
        }
        "duplicate" => r#"<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M4 16V5a2 2 0 0 1 2-2h11"/>"#,
        _ => r#"<circle cx="12" cy="12" r="10"/>"#,
    }
}

#[component]
pub fn Icon(name: &'static str, #[props(default = 18)] size: u32) -> Element {
    let inner = path(name);
    rsx! {
        svg {
            class: "icon",
            width: "{size}",
            height: "{size}",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            stroke_width: "2",
            stroke_linecap: "round",
            stroke_linejoin: "round",
            "aria-hidden": "true",
            dangerous_inner_html: inner,
        }
    }
}

/// The 2Secret logo (cyan "2" and shield).
#[component]
pub fn Logo(#[props(default = 28)] size: u32) -> Element {
    use twosecret_core::brand::{LOGO_COLOR, LOGO_PATH, LOGO_VIEWBOX};
    rsx! {
        svg { class: "logo", width: "{size}", height: "{size}", view_box: LOGO_VIEWBOX, "aria-hidden": "true",
            path { fill: LOGO_COLOR, fill_rule: "evenodd", d: LOGO_PATH }
        }
    }
}

/// Pick one of two icon names (keeps `rsx!` from treating the `if` as text).
pub fn either(cond: bool, a: &'static str, b: &'static str) -> &'static str {
    if cond {
        a
    } else {
        b
    }
}

/// The icons people can give a vault (stored in the vault's encrypted
/// metadata, so every member sees the same).
pub const VAULT_ICONS: [&str; 20] = [
    "vault",
    "user",
    "users",
    "key",
    "shield",
    "star",
    "globe",
    "code",
    "terminal",
    "server",
    "database",
    "cloud",
    "credit-card",
    "bank",
    "mail",
    "smartphone",
    "book",
    "gift",
    "award",
    "folder",
];

/// A vault's icon: the one chosen for it, else a vault or, when shared, people.
pub fn vault_icon(icon: &str, shared: bool) -> &'static str {
    VAULT_ICONS.into_iter().find(|i| *i == icon).unwrap_or(if shared { "users" } else { "vault" })
}

pub fn category_icon(c: Category) -> &'static str {
    match c {
        Category::Login => "globe",
        Category::Password => "key",
        Category::SecureNote => "note",
        Category::CreditCard => "credit-card",
        Category::Identity => "user",
        Category::BankAccount => "bank",
        Category::CryptoWallet => "hexagon",
        Category::SoftwareLicense => "package",
        Category::SshKey => "terminal",
        Category::ApiCredential => "code",
        Category::Database => "database",
        Category::Server => "server",
        Category::WirelessRouter => "wifi",
        Category::EmailAccount => "mail",
        Category::Passport => "book",
        Category::DriverLicense => "truck",
        Category::Membership => "award",
        Category::RewardProgram => "gift",
        Category::Document => "paperclip",
    }
}

/// Accent colour per category for the item avatars.
pub fn category_color(c: Category) -> &'static str {
    match c {
        Category::Login => "#3b5bdb",
        Category::Password => "#0c8599",
        Category::SecureNote => "#f08c00",
        Category::CreditCard => "#5f3dc4",
        Category::Identity => "#2b8a3e",
        Category::BankAccount => "#1971c2",
        Category::CryptoWallet => "#e67700",
        Category::SoftwareLicense => "#862e9c",
        Category::SshKey => "#343a40",
        Category::ApiCredential => "#495057",
        Category::Database => "#0b7285",
        Category::Server => "#364fc7",
        Category::WirelessRouter => "#1098ad",
        Category::EmailAccount => "#c2255c",
        Category::Passport => "#a61e4d",
        Category::DriverLicense => "#5c940d",
        Category::Membership => "#d9480f",
        Category::RewardProgram => "#e8590c",
        Category::Document => "#868e96",
    }
}

/// The account's profile photo, else the first letter of its name.
#[component]
pub fn AccountAvatar(
    name: String,
    #[props(default)] photo: Option<String>,
    #[props(default = 34)] size: u32,
) -> Element {
    let style = format!("width:{size}px;height:{size}px;font-size:{}px;margin:0", size * 44 / 100);
    match photo {
        Some(photo) => rsx! {
            img { class: "lock-avatar photo", src: "{photo}", alt: "", style, draggable: "false" }
        },
        None => {
            let initial: String = name.chars().next().map(|c| c.to_uppercase().collect()).unwrap_or_default();
            rsx! {
                div { class: "lock-avatar", style, "{initial}" }
            }
        }
    }
}

/// A coloured avatar: the website's icon, else the first letter of the title
/// on the category colour.
#[component]
pub fn ItemAvatar(
    category: Category,
    title: String,
    #[props(default = 36)] size: u32,
    /// A checked `data:image/…` URL (`ItemSummary::icon`, `WebsiteIcon::safe_image`).
    #[props(default)]
    icon: Option<String>,
) -> Element {
    if let Some(icon) = icon {
        let inner = size * 70 / 100;
        return rsx! {
            div { class: "avatar website", style: "width:{size}px;height:{size}px",
                img { src: "{icon}", alt: "", width: "{inner}", height: "{inner}", draggable: "false" }
            }
        };
    }
    let color = category_color(category);
    let letter: String =
        title.chars().find(|c| c.is_alphanumeric()).map(|c| c.to_uppercase().collect()).unwrap_or_default();
    let font = size * 45 / 100;
    rsx! {
        div {
            class: "avatar",
            style: "background:{color};width:{size}px;height:{size}px;font-size:{font}px",
            if letter.is_empty() {
                Icon { name: category_icon(category), size: size / 2 }
            } else {
                "{letter}"
            }
        }
    }
}
