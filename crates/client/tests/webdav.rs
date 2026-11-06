//! Vaults on a WebDAV server, end to end: a small WebDAV server (laid out
//! like Nextcloud's, at `/remote.php/dav/files/<user>/`), a real sync
//! server, and "devices" of one account.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use twosecret_client::folder::{self, MoveTo};
use twosecret_client::{self as client};
use twosecret_core::crypto::KdfParams;
use twosecret_core::item::Item;
use twosecret_core::session::Session;
use twosecret_server::{AppState, Config};

const PW: &str = "correct horse battery staple";
const DAV_USER: &str = "alice";
const DAV_PASSWORD: &str = "app-password-1";
const ROOT: &str = "/remote.php/dav/files/alice/";

#[derive(Default)]
struct Dav {
    /// Path → contents; folders end in `/` and have none.
    files: BTreeMap<String, Option<Vec<u8>>>,
    gets: usize,
}

type Shared = Arc<Mutex<Dav>>;

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

fn encode(path: &str) -> String {
    path.split('/')
        .map(|seg| {
            seg.bytes()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || b"-._~".contains(&c) {
                        (c as char).to_string()
                    } else {
                        format!("%{c:02X}")
                    }
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn parent(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(i) => trimmed[..=i].to_string(),
        None => "/".into(),
    }
}

fn entry(path: &str, contents: &Option<Vec<u8>>) -> String {
    let props = match contents {
        None => "<d:resourcetype><d:collection/></d:resourcetype>".to_string(),
        Some(c) => {
            let tag: u64 = c.iter().fold(1469598103934665603u64, |h, b| (h ^ *b as u64).wrapping_mul(1099511628211));
            format!("<d:resourcetype/><d:getcontentlength>{}</d:getcontentlength><d:getetag>&quot;{tag:x}&quot;</d:getetag>", c.len())
        }
    };
    format!(
        "<d:response><d:href>{}</d:href><d:propstat><d:prop>{props}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
        encode(path)
    )
}

async fn handle(State(dav): State<Shared>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    // "alice:app-password-1"
    if auth != "Basic YWxpY2U6YXBwLXBhc3N3b3JkLTE=" {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let path = decode(uri.path());
    let mut dav = dav.lock().unwrap();
    match method.as_str() {
        // Like Nextcloud: the server's root is no WebDAV folder.
        "PROPFIND" if !path.starts_with(ROOT) => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        "PROPFIND" => {
            let dir = format!("{}/", path.trim_end_matches('/'));
            let mut out = String::from(r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">"#);
            if let Some(None) = dav.files.get(&dir) {
                out.push_str(&entry(&dir, &None));
                let depth1 = headers.get("depth").is_some_and(|d| d == "1");
                if depth1 {
                    for (p, c) in dav.files.iter().filter(|(p, _)| p.as_str() != dir && parent(p) == dir) {
                        out.push_str(&entry(p, c));
                    }
                }
            } else if let Some(c @ Some(_)) = dav.files.get(&path) {
                out.push_str(&entry(&path, c));
            } else {
                return StatusCode::NOT_FOUND.into_response();
            }
            out.push_str("</d:multistatus>");
            (StatusCode::from_u16(207).unwrap(), out).into_response()
        }
        "GET" => match dav.files.get(&path).cloned() {
            Some(Some(c)) => {
                dav.gets += 1;
                (StatusCode::OK, c).into_response()
            }
            _ => StatusCode::NOT_FOUND.into_response(),
        },
        "PUT" => {
            if !matches!(dav.files.get(&parent(&path)), Some(None)) {
                return StatusCode::CONFLICT.into_response();
            }
            let created = dav.files.insert(path, Some(body.to_vec())).is_none();
            if created { StatusCode::CREATED } else { StatusCode::NO_CONTENT }.into_response()
        }
        "DELETE" => {
            let dir = format!("{}/", path.trim_end_matches('/'));
            let before = dav.files.len();
            dav.files.retain(|p, _| p != &path && !p.starts_with(&dir));
            if dav.files.len() == before { StatusCode::NOT_FOUND } else { StatusCode::NO_CONTENT }.into_response()
        }
        "MKCOL" => {
            let dir = format!("{}/", path.trim_end_matches('/'));
            if dav.files.contains_key(&dir) {
                return StatusCode::METHOD_NOT_ALLOWED.into_response();
            }
            if !matches!(dav.files.get(&parent(&dir)), Some(None)) {
                return StatusCode::CONFLICT.into_response();
            }
            dav.files.insert(dir, None);
            StatusCode::CREATED.into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

async fn start_dav() -> (String, Shared) {
    let dav: Shared = Arc::default();
    {
        let mut d = dav.lock().unwrap();
        for p in ["/", "/remote.php/", "/remote.php/dav/", "/remote.php/dav/files/", ROOT] {
            d.files.insert(p.into(), None);
        }
    }
    let app = axum::Router::new().fallback(handle).with_state(dav.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), dav)
}

async fn start_server() -> String {
    let state = AppState::in_memory(Config::default()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = twosecret_server::serve(listener, state).await;
    });
    format!("http://{addr}")
}

async fn sync_folders(s: &mut Session) {
    for outcome in folder::sync_folders(s).await.unwrap() {
        outcome.result.unwrap();
    }
}

fn webdav(url: &str) -> MoveTo {
    MoveTo::WebDav { url: url.into(), user: DAV_USER.into(), password: DAV_PASSWORD.into() }
}

#[tokio::test]
async fn a_vault_on_a_webdav_server_shared_by_two_devices() {
    let (url, dav) = start_dav().await;
    let (mut a, _) =
        Session::create_account("Alice", "alice@example.com", PW, KdfParams::insecure_for_tests(), "Personal").unwrap();
    let mut b = Session::open_with_account_key(a.profile().clone(), a.account_key().clone()).unwrap();

    // The server's address alone is enough: the Nextcloud folder is found.
    let work = folder::create_vault_in(&mut a, "Work stuff", "", &webdav(&url)).await.unwrap();
    let location = a.profile().vault(&work).unwrap().location.clone();
    assert!(location.is_webdav());
    let id = a.add_item(&work, Item::login("Mail", "alice", "pw-1", None)).unwrap();
    sync_folders(&mut a).await;
    {
        let d = dav.lock().unwrap();
        let names: Vec<&String> = d.files.keys().filter(|k| k.contains("/2Secret/Work stuff-")).collect();
        assert!(names.iter().any(|k| k.ends_with("/vault.json")), "{names:?}");
        assert!(names.iter().any(|k| k.contains("/items/")));
        // Nothing readable on the server.
        for c in d.files.values().flatten() {
            let text = String::from_utf8_lossy(c);
            assert!(!text.contains("pw-1") && !text.contains("Mail") && !text.contains(DAV_PASSWORD));
        }
    }

    // A wrong password says so.
    let err = folder::attach_webdav(&mut b, &url, DAV_USER, "wrong").await.unwrap_err();
    assert!(err.to_string().contains("user name or password"), "{err}");
    // The other device adds it.
    let added = folder::attach_webdav(&mut b, &url, DAV_USER, DAV_PASSWORD).await.unwrap();
    assert_eq!(added, work);
    assert_eq!(b.vault(&work).unwrap().name, "Work stuff");
    assert_eq!(b.item(&id).unwrap().password(), Some("pw-1"));

    // Changes go both ways.
    let mut item = b.item(&id).unwrap().clone();
    item.set_value("password", "pw-2");
    b.update_item(item).unwrap();
    sync_folders(&mut b).await;
    sync_folders(&mut a).await;
    assert_eq!(a.item(&id).unwrap().password(), Some("pw-2"));

    // Unchanged files are not fetched again.
    let before = dav.lock().unwrap().gets;
    sync_folders(&mut a).await;
    assert_eq!(dav.lock().unwrap().gets, before, "nothing changed, nothing fetched");

    // Deleted on one device, gone on the other.
    a.delete_item(&id).unwrap();
    sync_folders(&mut a).await;
    sync_folders(&mut b).await;
    assert!(b.item(&id).is_none());

    // Deleting the vault: the other device lets go of it too.
    folder::delete_folder_vault(&mut a, &work).await.unwrap();
    sync_folders(&mut b).await;
    assert!(b.vault(&work).is_none());
}

#[tokio::test]
async fn devices_follow_a_vault_to_a_webdav_server_by_themselves() {
    let (dav_url, dav) = start_dav().await;
    let url = start_server().await;
    let kdf = KdfParams::insecure_for_tests();
    let (mut laptop, sk) =
        client::signup(&url, "Alice", "alice@example.com", PW, None, "laptop", "Personal", kdf).await.unwrap();
    let work = laptop.create_vault("Work", "").unwrap();
    let one = laptop.add_item(&work, Item::login("One", "alice", "pw-1", None)).unwrap();
    client::sync(&mut laptop).await.unwrap();
    let mut phone = client::signin(&url, "alice@example.com", PW, &sk, "phone").await.unwrap();

    // Server -> WebDAV.
    folder::move_vault(&mut laptop, &work, webdav(&format!("{dav_url}{ROOT}"))).await.unwrap();
    assert!(laptop.vault(&work).unwrap().location.is_webdav());
    assert!(dav.lock().unwrap().files.keys().any(|k| k.contains("/2Secret/Work-")));

    // The phone needs nothing: the placeholder says where, with the
    // password (encrypted with the vault key).
    client::sync(&mut phone).await.unwrap();
    sync_folders(&mut phone).await;
    assert!(phone.vault(&work).unwrap().location.is_webdav());
    assert!(phone.item(&one).is_some());
    let two = phone.add_item(&work, Item::login("Two", "alice", "pw-2", None)).unwrap();
    sync_folders(&mut phone).await;
    sync_folders(&mut laptop).await;
    assert!(laptop.item(&two).is_some());

    // WebDAV -> server.
    folder::move_vault(&mut laptop, &work, MoveTo::Account).await.unwrap();
    sync_folders(&mut phone).await;
    client::sync(&mut phone).await.unwrap();
    assert!(phone.vault(&work).unwrap().location.is_account());
    assert!(phone.item(&one).is_some() && phone.item(&two).is_some());
}
