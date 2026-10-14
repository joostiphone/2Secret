//! The (small) platform specific layer: storage, timers, background work,
//! clipboard and file downloads. Everything else is shared by all targets.

use twosecret_core::storage::Storage;

pub use imp::*;

/// Which kind of app is running.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Desktop,
    Web,
    Mobile,
}

pub fn kind() -> Kind {
    if cfg!(feature = "web") && cfg!(target_arch = "wasm32") {
        Kind::Web
    } else if cfg!(feature = "mobile") {
        Kind::Mobile
    } else {
        Kind::Desktop
    }
}

thread_local! {
    static STORAGE: &'static dyn Storage = Box::leak(make_storage());
}

/// The storage backend of this platform.
pub fn storage() -> &'static dyn Storage {
    STORAGE.with(|s| *s)
}

/// JavaScript helper (desktop/mobile webviews) that copies text, falling back to `execCommand` where
/// the asynchronous clipboard API is unavailable (non-secure contexts).
#[cfg(not(target_arch = "wasm32"))]
const COPY_JS: &str = r#"
const text = await dioxus.recv();
let ok = false;
try { await navigator.clipboard.writeText(text); ok = true; } catch (e) {}
if (!ok) {
  const ta = document.createElement('textarea');
  ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
  document.body.appendChild(ta); ta.select();
  try { ok = document.execCommand('copy'); } catch (e) {}
  document.body.removeChild(ta);
}
return ok;
"#;

#[cfg(not(target_arch = "wasm32"))]
async fn js_copy(text: &str) -> bool {
    let eval = dioxus::document::eval(COPY_JS);
    if eval.send(text.to_string()).is_err() {
        return false;
    }
    eval.join::<bool>().await.unwrap_or(false)
}

/// Offer `content` as a file download in a webview.
#[allow(dead_code)]
#[cfg(not(target_arch = "wasm32"))]
async fn js_download(name: &str, mime: &str, content: &[u8]) -> bool {
    let eval = dioxus::document::eval(
        r#"
        const [name, mime, b64] = await dioxus.recv();
        const bin = atob(b64); const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        const url = URL.createObjectURL(new Blob([bytes], { type: mime }));
        const a = document.createElement('a'); a.href = url; a.download = name;
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 10000);
        return true;
        "#,
    );
    if eval.send((name.to_string(), mime.to_string(), twosecret_core::util::b64(content))).is_err() {
        return false;
    }
    eval.join::<bool>().await.unwrap_or(false)
}

/// Format a UNIX timestamp in the user's local time zone.
pub fn local_time(ts: i64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_opt(ts, 0).single() {
        Some(dt) => dt.format("%Y-%m-%d %H:%M").to_string(),
        None => twosecret_core::util::format_timestamp(ts),
    }
}

/// Format a UNIX timestamp as a local date.
pub fn local_date(ts: i64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_opt(ts, 0).single() {
        Some(dt) => dt.format("%Y-%m-%d").to_string(),
        None => twosecret_core::util::format_date(ts),
    }
}

/// Open a URL in the system browser / a new tab.
pub fn open_url(url: &str) {
    let url = if url.contains("://") { url.to_string() } else { format!("https://{url}") };
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return;
    }
    open_url_impl(&url);
}

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use super::*;
    use std::path::PathBuf;
    use twosecret_core::storage::{default_data_dir, FileStorage, MemoryStorage};

    pub(super) fn make_storage() -> Box<dyn Storage> {
        match FileStorage::new(data_dir()) {
            Ok(fs) => Box::new(fs),
            Err(e) => {
                eprintln!("2Secret: cannot use data directory ({e}); data will not be saved");
                Box::new(MemoryStorage::new())
            }
        }
    }

    pub fn data_dir() -> PathBuf {
        #[cfg(target_os = "android")]
        {
            if let Some(dir) = crate::android::data_dir() {
                return dir;
            }
        }
        #[cfg(target_os = "ios")]
        {
            if let Some(home) = std::env::var_os("HOME") {
                return PathBuf::from(home).join("Library").join("Application Support").join("2Secret");
            }
        }
        default_data_dir()
    }

    /// Nothing to prepare on native platforms.
    pub async fn prepare() {}

    /// Writes are stored before `write` returns.
    pub async fn flush() {}

    pub async fn sleep_ms(ms: u64) {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }

    /// Run CPU-heavy work (Argon2id) off the UI thread.
    pub async fn run_heavy<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = futures_channel::oneshot::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.await.expect("background task failed")
    }

    pub async fn copy_text(text: &str) -> bool {
        #[cfg(all(feature = "desktop", not(target_os = "ios"), not(target_os = "android")))]
        {
            if let Ok(mut cb) = arboard::Clipboard::new() {
                if cb.set_text(text.to_string()).is_ok() {
                    return true;
                }
            }
        }
        super::js_copy(text).await
    }

    /// Clear the clipboard if it still contains `text`.
    pub async fn clear_clipboard_if(text: &str) {
        #[cfg(all(feature = "desktop", not(target_os = "ios"), not(target_os = "android")))]
        {
            if let Ok(mut cb) = arboard::Clipboard::new() {
                if cb.get_text().map(|t| t == text).unwrap_or(false) {
                    let _ = cb.clear();
                }
                return;
            }
        }
        let _ = text;
        super::js_copy("").await;
    }

    /// Save a file for the user. Returns a description of where it went.
    pub async fn save_file(name: &str, _mime: &str, content: &[u8]) -> Result<String, String> {
        #[cfg(target_os = "android")]
        {
            return crate::android::save_file(name, _mime, content);
        }
        #[allow(unreachable_code)]
        let dir = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .map(|h| if cfg!(target_os = "ios") { h.join("Documents") } else { h.join("Downloads") })
            .filter(|d| d.is_dir())
            .unwrap_or_else(data_dir);
        let mut path = dir.join(name);
        let mut n = 1;
        while path.exists() {
            let stem = std::path::Path::new(name).file_stem().and_then(|s| s.to_str()).unwrap_or("file");
            let ext = std::path::Path::new(name).extension().and_then(|s| s.to_str()).unwrap_or("");
            path = dir.join(format!("{stem} ({n}).{ext}"));
            n += 1;
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write;
        opts.open(&path).and_then(|mut f| f.write_all(content)).map_err(|e| e.to_string())?;
        Ok(path.display().to_string())
    }

    pub fn device_name() -> String {
        let os = std::env::consts::OS;
        #[cfg(target_os = "android")]
        if let Some(model) = crate::android::device_model() {
            return format!("2Secret for Android ({model})");
        }
        let host = std::env::var("HOSTNAME")
            .ok()
            .or_else(|| std::env::var("COMPUTERNAME").ok())
            .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        match host {
            Some(h) => format!("2Secret for {os} ({h})"),
            None => format!("2Secret for {os}"),
        }
    }

    /// Preferred UI language of the system ("nl", "en", …).
    pub fn system_language() -> String {
        #[cfg(target_os = "android")]
        if let Some(lang) = crate::android::language() {
            return lang;
        }
        for var in ["LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"] {
            if let Ok(v) = std::env::var(var) {
                if !v.is_empty() && v != "C" && v != "POSIX" {
                    return v[..v.len().min(2)].to_lowercase();
                }
            }
        }
        "en".into()
    }

    /// Default server for new accounts (none on native apps).
    pub fn default_server() -> Option<String> {
        None
    }

    pub(super) fn open_url_impl(url: &str) {
        #[cfg(target_os = "android")]
        crate::android::open_url(url);
        // Through the operating system, like Dioxus does for links: the
        // webview's window.open only works during a click, and this runs
        // after the click went through Rust, so macOS and iOS (WKWebView)
        // and Linux (WebKitGTK) silently ignored it.
        #[cfg(not(target_os = "android"))]
        if let Err(e) = webbrowser::open(url) {
            eprintln!("2Secret: could not open {url}: {e}");
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use super::*;
    use twosecret_core::{Error, Result};

    use std::cell::RefCell;
    use std::collections::HashMap;

    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::{JsCast, JsValue};

    const DB_NAME: &str = "2secret";
    const STORE: &str = "kv";
    const LS_PREFIX: &str = "2secret.";

    thread_local! {
        /// Everything is read once at startup and served from memory.
        static CACHE: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
        static DB: RefCell<Option<web_sys::IdbDatabase>> = const { RefCell::new(None) };
    }

    fn ls() -> Option<web_sys::Storage> {
        web_sys::window().and_then(|w| w.local_storage().ok().flatten())
    }

    /// IndexedDB backed storage (falls back to `localStorage` when IndexedDB
    /// is unavailable). Writes are queued as IndexedDB transactions, which the
    /// browser applies in order.
    struct WebStorage;

    fn idb_write(key: &str, value: Option<&str>) -> bool {
        DB.with(|db| {
            let db = db.borrow();
            let Some(db) = db.as_ref() else { return false };
            let Ok(tx) = db.transaction_with_str_and_mode(STORE, web_sys::IdbTransactionMode::Readwrite) else {
                return false;
            };
            let Ok(store) = tx.object_store(STORE) else { return false };
            let key = JsValue::from_str(key);
            match value {
                Some(v) => store.put_with_key(&JsValue::from_str(v), &key).is_ok(),
                None => store.delete(&key).is_ok(),
            }
        })
    }

    impl Storage for WebStorage {
        fn read(&self, key: &str) -> Result<Option<String>> {
            Ok(CACHE.with(|c| c.borrow().get(key).cloned()))
        }
        fn write(&self, key: &str, value: &str) -> Result<()> {
            CACHE.with(|c| c.borrow_mut().insert(key.to_string(), value.to_string()));
            if !idb_write(key, Some(value)) {
                ls().ok_or_else(|| Error::Storage("no storage available".into()))?
                    .set_item(&format!("{LS_PREFIX}{key}"), value)
                    .map_err(|_| Error::Storage("the browser refused to store the vault (quota exceeded?)".into()))?;
            }
            Ok(())
        }
        fn delete(&self, key: &str) -> Result<()> {
            CACHE.with(|c| c.borrow_mut().remove(key));
            if !idb_write(key, None) {
                if let Some(ls) = ls() {
                    let _ = ls.remove_item(&format!("{LS_PREFIX}{key}"));
                }
            }
            Ok(())
        }
    }

    pub(super) fn make_storage() -> Box<dyn Storage> {
        Box::new(WebStorage)
    }

    /// Await an IndexedDB request.
    fn request(req: &web_sys::IdbRequest) -> impl std::future::Future<Output = std::result::Result<JsValue, JsValue>> {
        let (tx, rx) = futures_channel::oneshot::channel();
        let tx = std::rc::Rc::new(RefCell::new(Some(tx)));
        let (ok_req, err_req, tx_err) = (req.clone(), req.clone(), tx.clone());
        let on_success = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
            if let Some(t) = tx.borrow_mut().take() {
                let _ = t.send(ok_req.result());
            }
        });
        let on_error = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
            if let Some(t) = tx_err.borrow_mut().take() {
                let err = err_req.error().ok().flatten().map(JsValue::from).unwrap_or(JsValue::NULL);
                let _ = t.send(Err(err));
            }
        });
        req.set_onsuccess(Some(on_success.as_ref().unchecked_ref()));
        req.set_onerror(Some(on_error.as_ref().unchecked_ref()));
        async move {
            let result = rx.await.unwrap_or(Err(JsValue::NULL));
            drop((on_success, on_error));
            result
        }
    }

    async fn open_db() -> std::result::Result<web_sys::IdbDatabase, JsValue> {
        let factory = web_sys::window().ok_or(JsValue::NULL)?.indexed_db()?.ok_or(JsValue::NULL)?;
        let open = factory.open_with_u32(DB_NAME, 1)?;
        let on_upgrade = Closure::<dyn FnMut(web_sys::Event)>::new(move |e: web_sys::Event| {
            let Some(target) = e.target() else { return };
            let req: web_sys::IdbOpenDbRequest = target.unchecked_into();
            if let Ok(db) = req.result() {
                let db: web_sys::IdbDatabase = db.unchecked_into();
                let _ = db.create_object_store(STORE);
            }
        });
        open.set_onupgradeneeded(Some(on_upgrade.as_ref().unchecked_ref()));
        let db = request(&open).await?;
        drop(on_upgrade);
        Ok(db.unchecked_into())
    }

    async fn load_all(db: &web_sys::IdbDatabase) -> std::result::Result<HashMap<String, String>, JsValue> {
        let tx = db.transaction_with_str(STORE)?;
        let store = tx.object_store(STORE)?;
        // Issue both requests before awaiting so the transaction stays active.
        let keys_future = request(&store.get_all_keys()?);
        let values_future = request(&store.get_all()?);
        let keys: js_sys::Array = keys_future.await?.unchecked_into();
        let values: js_sys::Array = values_future.await?.unchecked_into();
        Ok(keys.iter().zip(values.iter()).filter_map(|(k, v)| Some((k.as_string()?, v.as_string()?))).collect())
    }

    /// Wait until earlier writes are stored: a read-only transaction starts
    /// only after the read/write transactions created before it have
    /// finished. A page that closes itself must wait, or the browser aborts
    /// them.
    pub async fn flush() {
        let req = DB.with(|db| {
            let db = db.borrow();
            let tx = db.as_ref()?.transaction_with_str(STORE).ok()?;
            tx.object_store(STORE).ok()?.count().ok()
        });
        if let Some(req) = req {
            let _ = request(&req).await;
        }
    }

    /// Load storage before the app starts (IndexedDB is asynchronous).
    pub async fn prepare() {
        let mut data = HashMap::new();
        match open_db().await {
            Ok(db) => {
                data = load_all(&db).await.unwrap_or_default();
                DB.with(|d| *d.borrow_mut() = Some(db));
                // Migrate data written by older versions to localStorage.
                if let Some(ls) = ls() {
                    let len = ls.length().unwrap_or(0);
                    let keys: Vec<String> = (0..len).filter_map(|i| ls.key(i).ok().flatten()).collect();
                    for full in keys.into_iter().filter(|k| k.starts_with(LS_PREFIX)) {
                        let key = full[LS_PREFIX.len()..].to_string();
                        if let Ok(Some(value)) = ls.get_item(&full) {
                            if !data.contains_key(&key) && idb_write(&key, Some(&value)) {
                                data.insert(key, value);
                            }
                        }
                        let _ = ls.remove_item(&full);
                    }
                }
            }
            Err(_) => {
                if let Some(ls) = ls() {
                    let len = ls.length().unwrap_or(0);
                    for i in 0..len {
                        if let Ok(Some(full)) = ls.key(i) {
                            if let (Some(key), Ok(Some(value))) = (full.strip_prefix(LS_PREFIX), ls.get_item(&full)) {
                                data.insert(key.to_string(), value);
                            }
                        }
                    }
                }
            }
        }
        CACHE.with(|c| *c.borrow_mut() = data);
    }

    pub async fn sleep_ms(ms: u64) {
        gloo_timers::future::TimeoutFuture::new(ms.min(u32::MAX as u64) as u32).await;
    }

    /// Browsers have no threads for us: yield once so the UI can show a
    /// progress state, then do the work.
    pub async fn run_heavy<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        sleep_ms(60).await;
        f()
    }

    pub async fn copy_text(text: &str) -> bool {
        let Some(window) = web_sys::window() else { return false };
        let promise = window.navigator().clipboard().write_text(text);
        wasm_bindgen_futures::JsFuture::from(promise).await.is_ok()
    }

    /// Browsers only let pages *read* the clipboard after a permission
    /// prompt, so the web vault clears it without checking its contents.
    pub async fn clear_clipboard_if(_text: &str) {
        let Some(window) = web_sys::window() else { return };
        let _ = wasm_bindgen_futures::JsFuture::from(window.navigator().clipboard().write_text("")).await;
    }

    pub async fn save_file(name: &str, mime: &str, content: &[u8]) -> Result<String, String> {
        use wasm_bindgen::JsCast;
        let fail = |_| "download failed".to_string();
        let window = web_sys::window().ok_or("no window")?;
        let document = window.document().ok_or("no document")?;
        let array = js_sys::Uint8Array::from(content);
        let parts = js_sys::Array::of1(&array);
        let opts = web_sys::BlobPropertyBag::new();
        opts.set_type(mime);
        let blob = web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &opts).map_err(fail)?;
        let url = web_sys::Url::create_object_url_with_blob(&blob).map_err(fail)?;
        let a: web_sys::HtmlAnchorElement =
            document.create_element("a").map_err(fail)?.dyn_into().map_err(|_| "download failed".to_string())?;
        a.set_href(&url);
        a.set_download(name);
        let body = document.body().ok_or("no body")?;
        let _ = body.append_child(&a);
        a.click();
        a.remove();
        // Give the browser time to start the download before revoking.
        sleep_ms(10_000).await;
        let _ = web_sys::Url::revoke_object_url(&url);
        Ok(name.to_string())
    }

    pub(super) fn open_url_impl(url: &str) {
        if let Some(w) = web_sys::window() {
            let _ = w.open_with_url_and_target_and_features(url, "_blank", "noopener,noreferrer");
        }
    }

    pub fn device_name() -> String {
        let ua = web_sys::window().and_then(|w| w.navigator().user_agent().ok()).unwrap_or_default();
        let browser = if ua.contains("Firefox") {
            "Firefox"
        } else if ua.contains("Edg/") {
            "Edge"
        } else if ua.contains("Chrome") {
            "Chrome"
        } else if ua.contains("Safari") {
            "Safari"
        } else {
            "browser"
        };
        format!("2Secret web ({browser})")
    }

    pub fn system_language() -> String {
        web_sys::window()
            .and_then(|w| w.navigator().language())
            .map(|l| l[..l.len().min(2)].to_lowercase())
            .unwrap_or_else(|| "en".into())
    }

    /// The web vault is usually served by the sync server itself.
    pub fn default_server() -> Option<String> {
        let loc = web_sys::window()?.location();
        let origin = loc.origin().ok()?;
        if origin.starts_with("http") {
            Some(origin)
        } else {
            None
        }
    }
}
