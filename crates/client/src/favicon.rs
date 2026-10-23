//! Fetching a website's icon (see [`twosecret_core::favicon`]) straight from
//! the website: its page for the icons it links to, else `/favicon.ico`; for
//! a login on a subdomain without an icon of its own, the main domain's.
//! Only `https:`, only public hosts (also after redirects), no cookies, small
//! limits; any failure just means no icon. An icon too large to keep with the
//! item is scaled down.

use std::io::Cursor;
use std::sync::OnceLock;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE};
use twosecret_core::favicon::{self, WebsiteIcon, MAX_ICON_BYTES, MAX_PAGE_BYTES};

/// How large an icon may be to download. Above [`MAX_ICON_BYTES`] it is
/// scaled down before it is kept.
const MAX_DOWNLOAD_BYTES: usize = 512 * 1024;

/// The sides in pixels of a scaled-down icon: sharp at the size the apps
/// show it on a high-resolution screen, smaller if that is still too large.
const ICON_SIDES: [u32; 2] = [96, 64];

const PAGE_ACCEPT: &str = "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8";
const IMAGE_ACCEPT: &str = "image/png,image/svg+xml,image/webp,image/*;q=0.8,*/*;q=0.5";

fn http() -> &'static reqwest::Client {
    static HTTP: OnceLock<reqwest::Client> = OnceLock::new();
    HTTP.get_or_init(|| {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
        reqwest::Client::builder()
            // Many websites turn away requests that do not look like a
            // browser's: 2Secret asks for the icon as the browser would.
            .user_agent(concat!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) ",
                "Version/26.0 Safari/605.1.15 2Secret/",
                env!("CARGO_PKG_VERSION")
            ))
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .https_only(true)
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 || !attempt.url().host_str().is_some_and(favicon::public_host) {
                    attempt.stop()
                } else {
                    attempt.follow()
                }
            }))
            .build()
            .unwrap_or_default()
    })
}

/// The icon of the website at `host` (see [`favicon::icon_host`]), or
/// `None`: no icon, not an image, offline.
pub async fn fetch(host: &str) -> Option<WebsiteIcon> {
    if !favicon::public_host(host) {
        return None;
    }
    if let Some(icon) = fetch_from(host, host).await {
        return Some(icon);
    }
    // login.example.com often only has the icon of example.com.
    let domain = favicon::main_domain(host).filter(|domain| domain != host)?;
    fetch_from(host, &domain).await
}

/// The icon of the website `site`, kept for the item's `host`.
async fn fetch_from(host: &str, site: &str) -> Option<WebsiteIcon> {
    let home = reqwest::Url::parse(&format!("https://{site}/")).ok()?;
    let (base, page) = match get(home.as_str(), PAGE_ACCEPT, MAX_PAGE_BYTES, true).await {
        Some((url, bytes)) => (url, String::from_utf8_lossy(&bytes).into_owned()),
        None => (home, String::new()),
    };
    for url in favicon::icon_urls(&page, &base).into_iter().take(5) {
        let bytes = if url.starts_with("data:") {
            favicon::data_url_bytes(&url)
        } else {
            get(&url, IMAGE_ACCEPT, MAX_DOWNLOAD_BYTES, false).await.map(|(_, bytes)| bytes)
        };
        if let Some(icon) = bytes.and_then(|bytes| keep(host, &bytes)) {
            return Some(icon);
        }
    }
    None
}

/// The icon as it is kept: as fetched when it is small enough, else scaled
/// down to a PNG (an SVG cannot be).
fn keep(host: &str, bytes: &[u8]) -> Option<WebsiteIcon> {
    if let Some(icon) = WebsiteIcon::from_bytes(host, bytes) {
        return Some(icon);
    }
    if bytes.len() <= MAX_ICON_BYTES || favicon::image_type(bytes)? == "image/svg+xml" {
        return None;
    }
    ICON_SIDES.into_iter().find_map(|side| WebsiteIcon::from_bytes(host, &shrink(bytes, side)?))
}

/// A raster image (PNG, ICO, JPEG, GIF, WebP) as a PNG of at most `side`
/// pixels square, keeping its shape.
fn shrink(bytes: &[u8], side: u32) -> Option<Vec<u8>> {
    let mut reader = image::ImageReader::new(Cursor::new(bytes)).with_guessed_format().ok()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(4096);
    limits.max_image_height = Some(4096);
    limits.max_alloc = Some(64 * 1024 * 1024);
    reader.limits(limits);
    let mut image = reader.decode().ok()?;
    if image.width() > side || image.height() > side {
        image = image.resize(side, side, image::imageops::FilterType::Lanczos3);
    }
    let mut png = Vec::new();
    image.write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png).ok()?;
    Some(png)
}

/// GET at most `limit` bytes: a page (`cut`) is cut off there, anything else
/// larger is dropped. Returns the final URL after redirects.
async fn get(url: &str, accept: &'static str, limit: usize, cut: bool) -> Option<(reqwest::Url, Vec<u8>)> {
    let mut response = http().get(url).header(ACCEPT, accept).send().await.ok()?.error_for_status().ok()?;
    if !cut && response.content_length().is_some_and(|len| len > limit as u64) {
        return None;
    }
    let final_url = response.url().clone();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        body.extend_from_slice(&chunk);
        if body.len() > limit {
            if !cut {
                return None;
            }
            body.truncate(limit);
            break;
        }
    }
    Some((final_url, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scales_down_large_icons() {
        // A 512-pixel PNG of noise, far larger than an icon may be.
        let mut seed = 7u32;
        let noise = image::RgbaImage::from_fn(512, 512, |_, _| {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            image::Rgba(seed.to_le_bytes())
        });
        let mut png = Vec::new();
        noise.write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png).unwrap();
        assert!(png.len() > MAX_ICON_BYTES);
        let icon = keep("example.com", &png).unwrap();
        let kept = favicon::data_url_bytes(&icon.image).unwrap();
        assert!(kept.len() <= MAX_ICON_BYTES);
        let small = image::load_from_memory(&kept).unwrap();
        assert!(small.width() <= 96 && small.height() <= 96);
        // Not an image: nothing.
        assert_eq!(keep("example.com", &[b'x'; MAX_ICON_BYTES + 1]), None);
    }

    #[tokio::test]
    async fn refuses_private_hosts_without_asking() {
        for host in ["localhost", "192.168.1.1", "router", "nas.local"] {
            assert_eq!(fetch(host).await, None, "{host}");
        }
    }
}
