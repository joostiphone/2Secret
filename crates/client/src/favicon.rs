//! Fetching a website's icon (see [`twosecret_core::favicon`]) straight from
//! the website: its page for the icons it links to, else `/favicon.ico`.
//! Only `https:`, only public hosts (also after redirects), no cookies, small
//! limits; any failure just means no icon.

use std::time::Duration;

use twosecret_core::favicon::{self, WebsiteIcon, MAX_ICON_BYTES, MAX_PAGE_BYTES};

fn http() -> reqwest::Client {
    reqwest::Client::builder()
        // Some websites turn away requests that do not look like a browser.
        .user_agent(concat!("Mozilla/5.0 (compatible; 2Secret/", env!("CARGO_PKG_VERSION"), ")"))
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
}

/// The icon of the website at `host` (see [`favicon::icon_host`]), or
/// `None`: no icon, not an image, too large, offline.
pub async fn fetch(host: &str) -> Option<WebsiteIcon> {
    if !favicon::public_host(host) {
        return None;
    }
    let http = http();
    let home = reqwest::Url::parse(&format!("https://{host}/")).ok()?;
    let (base, page) = match get(&http, home.as_str(), MAX_PAGE_BYTES).await {
        Some((url, bytes)) => (url, String::from_utf8_lossy(&bytes).into_owned()),
        None => (home, String::new()),
    };
    for url in favicon::icon_urls(&page, &base).into_iter().take(4) {
        let bytes = if url.starts_with("data:") {
            favicon::data_url_bytes(&url)
        } else {
            get(&http, &url, MAX_ICON_BYTES).await.map(|(_, bytes)| bytes)
        };
        if let Some(icon) = bytes.and_then(|bytes| WebsiteIcon::from_bytes(host, &bytes)) {
            return Some(icon);
        }
    }
    None
}

/// GET at most `limit` bytes (a page is cut off there, anything else is
/// dropped); returns the final URL after redirects.
async fn get(http: &reqwest::Client, url: &str, limit: usize) -> Option<(reqwest::Url, Vec<u8>)> {
    let mut response = http.get(url).send().await.ok()?.error_for_status().ok()?;
    let page = limit == MAX_PAGE_BYTES;
    if !page && response.content_length().is_some_and(|len| len > limit as u64) {
        return None;
    }
    let final_url = response.url().clone();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        body.extend_from_slice(&chunk);
        if body.len() > limit {
            if !page {
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

    #[tokio::test]
    async fn refuses_private_hosts_without_asking() {
        for host in ["localhost", "192.168.1.1", "router", "nas.local"] {
            assert_eq!(fetch(host).await, None, "{host}");
        }
    }
}
