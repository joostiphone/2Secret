//! Website icons for logins. The apps fetch an icon straight from the
//! website of a login (no icon service in between) and keep it, end-to-end
//! encrypted like the rest of the item, in [`crate::item::Item::icon`], so
//! every device shows it without asking the website again. This module holds
//! the parts without network: which host to ask, which icon in a page to
//! take and whether the bytes are an image.

use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::item::Item;
use crate::util::url_host;

/// Icons larger than this are not kept (they are synced with the item).
pub const MAX_ICON_BYTES: usize = 24 * 1024;

/// How much of a website's page is read to find its icons.
pub const MAX_PAGE_BYTES: usize = 256 * 1024;

/// An item's website icon. Wiped from memory with the item: it shows which
/// websites someone has an account on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct WebsiteIcon {
    /// The host it was fetched for (see [`icon_host`]).
    pub host: String,
    /// The image as a `data:image/…;base64,…` URL.
    pub image: String,
}

impl WebsiteIcon {
    /// An icon from downloaded bytes, if they are an image of acceptable size.
    pub fn from_bytes(host: &str, bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > MAX_ICON_BYTES {
            return None;
        }
        let mime = image_type(bytes)?;
        let data = base64::engine::general_purpose::STANDARD.encode(bytes);
        Some(Self { host: host.to_string(), image: format!("data:{mime};base64,{data}") })
    }

    /// The image if it is a data URL of an image type the apps show; icons
    /// come from other people's items too, so this is checked on display.
    pub fn safe_image(&self) -> Option<&str> {
        is_image_data_url(&self.image).then_some(self.image.as_str())
    }
}

/// Whether a string is a `data:` URL of an image type the apps show (icons,
/// profile photos).
pub fn is_image_data_url(url: &str) -> bool {
    url.strip_prefix("data:")
        .and_then(|rest| rest.split_once(";base64,"))
        .is_some_and(|(mime, data)| IMAGE_TYPES.contains(&mime) && !data.is_empty())
}

const IMAGE_TYPES: [&str; 6] = ["image/png", "image/x-icon", "image/gif", "image/jpeg", "image/webp", "image/svg+xml"];

/// The image type of some bytes, by their content (never by what a server
/// says). SVG is safe here: the apps show icons with `<img>`, where scripts
/// in SVG do not run.
pub fn image_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0, 0, 1, 0]) {
        Some("image/x-icon")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        let head = String::from_utf8_lossy(&bytes[..bytes.len().min(1024)]).to_lowercase();
        (head.contains("<svg") && !head.contains("<html")).then_some("image/svg+xml")
    }
}

/// The host to fetch an icon for: that of the item's first website, without
/// "www.". Only public names: no IP addresses, no single-label or local
/// names (a shared item must not make other people's devices contact their
/// own network).
pub fn icon_host(item: &Item) -> Option<String> {
    let host = url_host(item.urls.iter().find(|u| !u.trim().is_empty())?)?;
    let host = host.trim_end_matches('.').to_string();
    public_host(&host).then_some(host)
}

/// Whether a host is a public DNS name the apps may fetch icons from. The
/// host is read the way a request reads it, so `127.1` and `0x7f.1` are the
/// IP addresses they stand for, and `nas.local.` is `nas.local`.
pub fn public_host(host: &str) -> bool {
    if host.is_empty() || host.contains(['/', '\\', '@', ':', '?', '#']) {
        return false;
    }
    let Ok(url) = url::Url::parse(&format!("https://{host}/")) else { return false };
    let Some(url::Host::Domain(name)) = url.host() else { return false };
    let name = name.trim_end_matches('.');
    if !name.contains('.') {
        return false;
    }
    const PRIVATE: [&str; 6] = [".local", ".localhost", ".internal", ".lan", ".home.arpa", ".test"];
    !PRIVATE.iter().any(|suffix| name.ends_with(suffix))
        && psl::suffix_str(name).is_some_and(|suffix| suffix != name && psl::domain_str(name).is_some())
}

/// Whether an item should get a (new) icon: it has a public website and no
/// icon for that host yet.
pub fn wants_icon(item: &Item) -> bool {
    icon_host(item).is_some_and(|host| item.icon.as_ref().is_none_or(|icon| icon.host != host))
}

/// The icons a page links to, best first, as absolute `https:` (or `data:`)
/// URLs, followed by `/favicon.ico`. The best is the smallest one of at
/// least 32 pixels; SVG fits any size.
pub fn icon_urls(page: &str, base: &url::Url) -> Vec<String> {
    let head = page.get(..page.len().min(MAX_PAGE_BYTES)).unwrap_or(page);
    let head = match head.to_ascii_lowercase().find("</head") {
        Some(end) => &head[..end],
        None => head,
    };
    let mut found: Vec<(u32, String)> = Vec::new();
    for tag in tags(head, "link") {
        let rel = attribute(tag, "rel").unwrap_or_default().to_ascii_lowercase();
        let rels: Vec<&str> = rel.split_ascii_whitespace().collect();
        let touch = rels.iter().any(|r| r.starts_with("apple-touch-icon"));
        if !(rels.contains(&"icon") || touch) {
            continue;
        }
        let Some(href) = attribute(tag, "href").filter(|h| !h.trim().is_empty()) else { continue };
        let Some(url) = absolute(base, href.trim()) else { continue };
        let svg = attribute(tag, "type").is_some_and(|t| t.eq_ignore_ascii_case("image/svg+xml"))
            || url.split(['?', '#']).next().is_some_and(|path| path.to_ascii_lowercase().ends_with(".svg"));
        let size = attribute(tag, "sizes").and_then(|s| largest_size(&s)).unwrap_or(if touch { 180 } else { 32 });
        let score = if svg {
            1
        } else if size >= 32 {
            size - 32 + 2
        } else {
            1000 + (32 - size)
        };
        if !found.iter().any(|(_, u)| *u == url) {
            found.push((score, url));
        }
    }
    found.sort_by_key(|(score, _)| *score);
    let mut urls: Vec<String> = found.into_iter().map(|(_, url)| url).collect();
    if let Ok(ico) = base.join("/favicon.ico") {
        if !urls.contains(&ico.to_string()) {
            urls.push(ico.to_string());
        }
    }
    urls
}

/// The bytes of a `data:image/…;base64,…` URL.
pub fn data_url_bytes(url: &str) -> Option<Vec<u8>> {
    let rest = url.strip_prefix("data:")?;
    let (mime, data) = rest.split_once(";base64,")?;
    if !mime.starts_with("image/") {
        return None;
    }
    base64::engine::general_purpose::STANDARD.decode(data.trim()).ok()
}

fn absolute(base: &url::Url, href: &str) -> Option<String> {
    if href.starts_with("data:") {
        return Some(href.to_string());
    }
    let url = base.join(href).ok()?;
    (url.scheme() == "https" && url.host_str().is_some_and(public_host)).then(|| url.to_string())
}

/// The largest square size in a `sizes` attribute ("16x16 32x32"); "any"
/// counts as 64.
fn largest_size(sizes: &str) -> Option<u32> {
    sizes
        .split_ascii_whitespace()
        .filter_map(|s| {
            if s.eq_ignore_ascii_case("any") {
                return Some(64);
            }
            let (w, h) = s.to_ascii_lowercase().split_once('x').map(|(w, h)| (w.to_string(), h.to_string()))?;
            Some(w.parse::<u32>().ok()?.max(h.parse().ok()?))
        })
        .max()
}

/// The contents of every `<name …>` tag, between the name and the `>`.
fn tags<'a>(html: &'a str, name: &str) -> Vec<&'a str> {
    let lower = html.to_ascii_lowercase();
    let open = format!("<{name}");
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(start) = lower[from..].find(&open).map(|i| from + i + open.len()) {
        let boundary = lower[start..].chars().next().is_some_and(|c| c.is_ascii_whitespace() || c == '/' || c == '>');
        let Some(end) = lower[start..].find('>').map(|i| start + i) else { break };
        if boundary {
            out.push(&html[start..end]);
        }
        from = end;
    }
    out
}

/// An attribute's value in the contents of a tag (quoted or not).
fn attribute(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let bytes = tag.as_bytes();
    let mut from = 0;
    while let Some(found) = lower[from..].find(name).map(|i| from + i) {
        from = found + name.len();
        let before = found.checked_sub(1).map(|i| bytes[i]);
        if before.is_some_and(|b| !(b as char).is_ascii_whitespace()) {
            continue;
        }
        let rest = tag[from..].trim_start();
        let Some(value) = rest.strip_prefix('=') else { continue };
        let value = value.trim_start();
        let parsed = match value.chars().next() {
            Some(quote @ ('"' | '\'')) => value[1..].split(quote).next().unwrap_or_default(),
            _ => value.split(|c: char| c.is_ascii_whitespace() || c == '>').next().unwrap_or_default(),
        };
        return Some(decode_entities(parsed));
    }
    None
}

fn decode_entities(text: &str) -> String {
    text.replace("&amp;", "&").replace("&quot;", "\"").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::Category;

    fn login(url: &str) -> Item {
        let mut item = Item::new(Category::Login, "Example");
        item.urls = vec![url.to_string()];
        item
    }

    #[test]
    fn hosts_to_ask() {
        assert_eq!(icon_host(&login("https://www.example.com/login")).as_deref(), Some("example.com"));
        assert_eq!(icon_host(&login("accounts.google.com")).as_deref(), Some("accounts.google.com"));
        for private in ["http://192.168.1.1", "https://[::1]/", "router", "nas.local", "printer.lan", "localhost:8080"]
        {
            assert_eq!(icon_host(&login(private)), None, "{private}");
        }
        assert_eq!(icon_host(&login("https://co.uk")), None);
        assert_eq!(icon_host(&Item::new(Category::Login, "No website")), None);
        // Short and hexadecimal IPv4 forms, as a request would read them.
        for private in ["foo://169.254.43518", "ssh://0x7f.1", "foo://192.168.1", "foo://127.1"] {
            assert_eq!(icon_host(&login(private)), None, "{private}");
        }
    }

    #[test]
    fn public_hosts_only() {
        assert!(public_host("example.com"));
        assert!(public_host("Example.COM."));
        for private in
            ["nas.local.", "printer.lan.", "0x7f.1", "127.1", "2130706433", "[::1]", "a.com:8080", "a@b.com", ""]
        {
            assert!(!public_host(private), "{private}");
        }
    }

    #[test]
    fn wants_an_icon_for_a_new_host_only() {
        let mut item = login("https://example.com");
        assert!(wants_icon(&item));
        item.icon = Some(WebsiteIcon { host: "example.com".into(), image: "data:image/png;base64,AA==".into() });
        assert!(!wants_icon(&item));
        item.urls = vec!["https://example.org".into()];
        assert!(wants_icon(&item));
        // Saving drops the icon of the old website.
        item.normalize();
        assert_eq!(item.icon, None);
    }

    #[test]
    fn picks_the_best_icon() {
        let base = url::Url::parse("https://example.com/login").unwrap();
        let page = r#"<html><head>
            <link rel="apple-touch-icon" href="/apple.png">
            <LINK REL="icon" sizes="16x16" href="/16.png">
            <link rel=icon sizes="32x32 48x48" href="icons/48.png">
            <link rel="shortcut icon" href="https://cdn.example.com/fav.ico?v=2&amp;x=1">
            <link rel="mask-icon" href="/mask.svg">
            <link rel="stylesheet" href="/style.css">
            <link rel="icon" href="http://example.com/insecure.png">
            </head><body><link rel="icon" href="/body.png"></body></html>"#;
        assert_eq!(
            icon_urls(page, &base),
            [
                "https://cdn.example.com/fav.ico?v=2&x=1",
                "https://example.com/icons/48.png",
                "https://example.com/apple.png",
                "https://example.com/16.png",
                "https://example.com/favicon.ico",
            ]
        );
        let svg =
            r#"<link rel="icon" type="image/svg+xml" href="/icon.svg"><link rel="icon" sizes="64x64" href="/64.png">"#;
        assert_eq!(icon_urls(svg, &base)[0], "https://example.com/icon.svg");
        assert_eq!(icon_urls("", &base), ["https://example.com/favicon.ico"]);
    }

    #[test]
    fn checks_the_image() {
        let png = b"\x89PNG\r\n\x1a\nrest";
        let icon = WebsiteIcon::from_bytes("example.com", png).unwrap();
        assert!(icon.image.starts_with("data:image/png;base64,"));
        assert_eq!(icon.safe_image(), Some(icon.image.as_str()));
        assert_eq!(data_url_bytes(&icon.image).unwrap(), png);
        assert_eq!(image_type(&[0, 0, 1, 0, 1, 0]), Some("image/x-icon"));
        assert_eq!(
            image_type(b"<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"/>"),
            Some("image/svg+xml")
        );
        assert_eq!(image_type(b"<!doctype html><html><svg></svg></html>"), None);
        assert!(WebsiteIcon::from_bytes("example.com", b"<html>not found</html>").is_none());
        assert!(WebsiteIcon::from_bytes("example.com", &[0x89; MAX_ICON_BYTES + 1]).is_none());
        let bad = WebsiteIcon { host: "example.com".into(), image: "javascript:alert(1)".into() };
        assert_eq!(bad.safe_image(), None);
        let html = WebsiteIcon { host: "example.com".into(), image: "data:text/html;base64,PGI+".into() };
        assert_eq!(html.safe_image(), None);
    }
}
