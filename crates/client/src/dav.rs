//! A small WebDAV client for vaults kept on a WebDAV server (Nextcloud,
//! ownCloud, a Synology NAS, Koofr, Fastmail…): listing a folder, reading,
//! writing and removing files, and making folders. Only what a vault folder
//! needs ([`crate::folder`]).

use std::collections::HashMap;
use std::sync::Mutex;

use reqwest::{Method, StatusCode};

use crate::{Error, Result};

/// One entry of a folder listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub dir: bool,
    /// Changes whenever the file does (else its size and time stand in).
    pub tag: String,
}

/// A folder on a WebDAV server, with the account to reach it.
#[derive(Clone)]
pub struct Dav {
    /// The folder, ending in `/`.
    base: String,
    user: String,
    password: String,
    http: reqwest::Client,
}

impl std::fmt::Debug for Dav {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dav").field("base", &self.base).field("user", &self.user).finish_non_exhaustive()
    }
}

/// A WebDAV address typed by a person, made complete: `https://` added, a
/// `/` at the end. Plain `http://` only for this device.
pub fn normalize_url(url: &str) -> Result<String> {
    let url = url.trim();
    let url = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else if url.starts_with("localhost") || url.starts_with("127.0.0.1") {
        format!("http://{url}")
    } else {
        format!("https://{url}")
    };
    let parsed = url::Url::parse(&url).map_err(|_| Error::Core(twosecret_core::Error::invalid("not a web address")))?;
    if parsed.scheme() == "http" && !matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")) {
        return Err(Error::InsecureServer);
    }
    let mut url = parsed.to_string();
    if let Some(i) = url.find(['?', '#']) {
        url.truncate(i);
    }
    if !url.ends_with('/') {
        url.push('/');
    }
    Ok(url)
}

/// Percent-encode one path segment.
fn encode_segment(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const PROPFIND_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getetag/><d:getcontentlength/><d:getlastmodified/></d:prop></d:propfind>"#;

/// Files read before, by address and tag: unchanged files are not fetched
/// again.
static CACHE: Mutex<Option<HashMap<String, (String, String)>>> = Mutex::new(None);

impl Dav {
    pub fn new(url: &str, user: &str, password: &str) -> Result<Dav> {
        Ok(Dav {
            base: normalize_url(url)?,
            user: user.to_string(),
            password: password.to_string(),
            http: crate::build_http(),
        })
    }

    pub fn url(&self) -> &str {
        &self.base
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    /// The folder `rel` (`a/b/`) inside this one.
    pub fn join(&self, rel: &str) -> Dav {
        let mut d = self.clone();
        d.base = self.address(rel);
        if !d.base.ends_with('/') {
            d.base.push('/');
        }
        d
    }

    /// The address of `rel` (`items/x.json`, `items/`) inside the folder.
    fn address(&self, rel: &str) -> String {
        let trailing = rel.ends_with('/');
        let mut url = self.base.clone();
        let parts: Vec<String> = rel.split('/').filter(|p| !p.is_empty()).map(encode_segment).collect();
        url.push_str(&parts.join("/"));
        if trailing && !parts.is_empty() {
            url.push('/');
        }
        url
    }

    async fn send(
        &self,
        method: Method,
        rel: &str,
        depth: Option<&str>,
        body: Option<String>,
    ) -> Result<reqwest::Response> {
        let mut req = self.http.request(method, self.address(rel)).basic_auth(&self.user, Some(&self.password));
        if let Some(depth) = depth {
            req = req.header("Depth", depth).header("Content-Type", "application/xml; charset=utf-8");
        }
        if let Some(body) = body {
            req = req.body(body);
        }
        let resp = req.send().await?;
        match resp.status() {
            StatusCode::UNAUTHORIZED => Err(Error::Api {
                status: 401,
                code: "webdav_auth".into(),
                message: "the WebDAV server did not accept the user name or password".into(),
            }),
            StatusCode::FORBIDDEN => Err(Error::Api {
                status: 403,
                code: "webdav_forbidden".into(),
                message: "the WebDAV server does not allow this".into(),
            }),
            _ => Ok(resp),
        }
    }

    fn failed(what: &str, status: StatusCode) -> Error {
        Error::Api {
            status: status.as_u16(),
            code: "webdav".into(),
            message: format!("WebDAV {what} failed: {status}"),
        }
    }

    /// The entries of the folder `rel` (`""` for this folder). `None` when
    /// there is no such folder.
    pub async fn list(&self, rel: &str) -> Result<Option<Vec<Entry>>> {
        let resp = self
            .send(Method::from_bytes(b"PROPFIND").expect("valid method"), rel, Some("1"), Some(PROPFIND_BODY.into()))
            .await?;
        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if status.as_u16() != 207 {
            return Err(Self::failed("listing", status));
        }
        let own = url::Url::parse(&self.address(if rel.is_empty() { "" } else { rel }))
            .map(|u| decode(u.path()).trim_end_matches('/').to_string())
            .unwrap_or_default();
        let text = resp.text().await?;
        Ok(Some(
            parse_multistatus(&text)
                .into_iter()
                .filter(|(path, _)| path.trim_end_matches('/') != own)
                .map(|(_, e)| e)
                .collect(),
        ))
    }

    /// Whether the folder exists and these credentials can read it.
    pub async fn check(&self) -> Result<bool> {
        let resp = self
            .send(Method::from_bytes(b"PROPFIND").expect("valid method"), "", Some("0"), Some(PROPFIND_BODY.into()))
            .await?;
        // Anything but a listing (a web page, 404, 405): no WebDAV folder here.
        Ok(resp.status().as_u16() == 207)
    }

    /// Read a file; `None` when it is not there. `tag` (from a listing)
    /// lets an unchanged file come from memory.
    pub async fn get(&self, rel: &str, tag: Option<&str>) -> Result<Option<String>> {
        let address = self.address(rel);
        if let Some(tag) = tag {
            if let Some((t, body)) = CACHE.lock().ok().and_then(|c| c.as_ref().and_then(|c| c.get(&address).cloned())) {
                if t == tag {
                    return Ok(Some(body));
                }
            }
        }
        let resp = self.send(Method::GET, rel, None, None).await?;
        match resp.status() {
            StatusCode::NOT_FOUND => Ok(None),
            s if s.is_success() => {
                let body = resp.text().await?;
                if let (Some(tag), Ok(mut cache)) = (tag, CACHE.lock()) {
                    cache.get_or_insert_with(HashMap::new).insert(address, (tag.to_string(), body.clone()));
                }
                Ok(Some(body))
            }
            s => Err(Self::failed("reading", s)),
        }
    }

    /// Write a file (replacing it).
    pub async fn put(&self, rel: &str, contents: &str) -> Result<()> {
        let resp = self.send(Method::PUT, rel, None, Some(contents.to_string())).await?;
        match resp.status() {
            s if s.is_success() => Ok(()),
            s => Err(Self::failed("writing", s)),
        }
    }

    /// Remove a file (no matter if it is gone already).
    pub async fn delete(&self, rel: &str) -> Result<()> {
        let resp = self.send(Method::DELETE, rel, None, None).await?;
        match resp.status() {
            StatusCode::NOT_FOUND => Ok(()),
            s if s.is_success() => Ok(()),
            s => Err(Self::failed("removing", s)),
        }
    }

    /// Make the folder `rel` (no matter if it is there already).
    pub async fn mkcol(&self, rel: &str) -> Result<()> {
        let resp = self.send(Method::from_bytes(b"MKCOL").expect("valid method"), rel, None, None).await?;
        match resp.status() {
            // 405: it exists.
            s if s.is_success() || s == StatusCode::METHOD_NOT_ALLOWED => Ok(()),
            s => Err(Self::failed("making a folder", s)),
        }
    }
}

/// The responses of a `207 Multi-Status`: the decoded path of each and its
/// entry. Element names are matched without their namespace prefix.
fn parse_multistatus(xml: &str) -> Vec<(String, Entry)> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut out = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut text = String::new();
    let (mut href, mut etag, mut len, mut modified, mut dir, mut ok) =
        (String::new(), String::new(), String::new(), String::new(), false, true);
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                if name == "response" {
                    (href, etag, len, modified, dir, ok) =
                        (String::new(), String::new(), String::new(), String::new(), false, true);
                }
                if name == "collection" {
                    dir = true;
                }
                text.clear();
                stack.push(name);
            }
            Ok(Event::Empty(e)) => {
                if e.local_name().as_ref() == b"collection" {
                    dir = true;
                }
            }
            Ok(Event::Text(t)) => text.push_str(&t.decode().unwrap_or_default()),
            Ok(Event::CData(t)) => text.push_str(&String::from_utf8_lossy(&t.into_inner())),
            Ok(Event::GeneralRef(r)) => {
                let name = r.decode().unwrap_or_default().into_owned();
                match r.resolve_char_ref() {
                    Ok(Some(c)) => text.push(c),
                    _ => text.push_str(quick_xml::escape::resolve_predefined_entity(&name).unwrap_or("")),
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                stack.pop();
                let parent = stack.last().map(String::as_str);
                match name.as_str() {
                    "href" if parent == Some("response") => href = text.trim().to_string(),
                    "getetag" => etag = text.trim().to_string(),
                    "getcontentlength" => len = text.trim().to_string(),
                    "getlastmodified" => modified = text.trim().to_string(),
                    // A response that failed as a whole (a propstat that did
                    // not only carries no properties of ours).
                    "status" if parent == Some("response") => ok = text.contains(" 2"),
                    "response" if ok && !href.is_empty() => {
                        let path = match url::Url::parse(&href) {
                            Ok(u) => decode(u.path()),
                            Err(_) => decode(href.split(['?', '#']).next().unwrap_or(&href)),
                        };
                        let name = path.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string();
                        let tag = if etag.is_empty() { format!("{len}|{modified}") } else { etag.clone() };
                        out.push((path, Entry { name, dir, tag }));
                    }
                    _ => {}
                }
                text.clear();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert_eq!(
            normalize_url("cloud.example.com/remote.php/dav/files/joost").unwrap(),
            "https://cloud.example.com/remote.php/dav/files/joost/"
        );
        assert_eq!(normalize_url("localhost:8080").unwrap(), "http://localhost:8080/");
        assert!(matches!(normalize_url("http://nas.example.com/dav"), Err(Error::InsecureServer)));
        let d = Dav::new("https://h/dav/", "u", "p").unwrap();
        assert_eq!(
            d.address("2Secret/Work stuff-1a2b/items/x~t.json"),
            "https://h/dav/2Secret/Work%20stuff-1a2b/items/x~t.json"
        );
        assert_eq!(d.join("2Secret/A b/").url(), "https://h/dav/2Secret/A%20b/");
        assert_eq!(decode("Work%20stuff%C3%A9"), "Work stuffé");
    }

    #[test]
    fn multistatus_of_nextcloud_and_others() {
        let xml = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns" xmlns:oc="http://owncloud.org/ns">
 <d:response><d:href>/remote.php/dav/files/joost/2Secret/Work-1a2b/</d:href>
  <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>&quot;65a&quot;</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
 <d:response><d:href>/remote.php/dav/files/joost/2Secret/Work-1a2b/vault.json</d:href>
  <d:propstat><d:prop><d:resourcetype/><d:getetag>&quot;e1&quot;</d:getetag><d:getcontentlength>312</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
 <d:response><d:href>/remote.php/dav/files/joost/2Secret/Work-1a2b/items/</d:href>
  <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
</d:multistatus>"#;
        let entries = parse_multistatus(xml);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[1].1, Entry { name: "vault.json".into(), dir: false, tag: "\"e1\"".into() });
        assert!(entries[2].1.dir && entries[2].1.name == "items");
        // Without prefixes, absolute hrefs, no etag.
        let xml = r#"<multistatus xmlns="DAV:"><response><href>https://nas:5006/home/a%20b/x~t.json</href>
<propstat><prop><getcontentlength>9</getcontentlength><getlastmodified>Fri, 06 Nov 2026 10:00:00 GMT</getlastmodified><resourcetype/></prop><status>HTTP/1.1 200 OK</status></propstat></response></multistatus>"#;
        let entries = parse_multistatus(xml);
        assert_eq!(entries[0].0, "/home/a b/x~t.json");
        assert_eq!(entries[0].1.name, "x~t.json");
        assert!(entries[0].1.tag.starts_with("9|Fri"));
    }
}
