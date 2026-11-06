//! Vaults in storage folders (iCloud Drive, Dropbox, Google Drive, OneDrive,
//! Syncthing, a network share): reading and writing their files, finding the
//! storage apps' folders, and moving vaults between the server, this device
//! and folders. The format and the merge rules are in
//! [`twosecret_core::folder`]; `docs/VAULT-FOLDER.md` describes them.
//!
//! File access runs on its own thread: opening a file a storage app has not
//! downloaded yet can wait for the network.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use futures_util::stream::{self, StreamExt};
use twosecret_core::api::UpdateVaultRequest;
use twosecret_core::folder::{
    self as format, FolderPlan, FolderReport, ItemFile, MetaFile, Snapshot, VaultFile, ITEMS_DIR, MOVED_FILE,
    PARENT_DIR, TEMP_PREFIX, VAULT_FILE,
};
use twosecret_core::profile::{FolderService, MoveTarget, MovedTo, SyncState, VaultLocation};
use twosecret_core::session::Session;
use twosecret_core::util::now;

use crate::dav::Dav;
use crate::flows::{client_for, sync, SessionAccess};
use crate::{Error, Result};

/// Run blocking file work on its own thread.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.await.map_err(|_| Error::Core(twosecret_core::Error::Storage("the folder could not be read".into())))
}

fn io_error(path: &Path, e: std::io::Error) -> Error {
    Error::Core(twosecret_core::Error::Storage(format!("{}: {e}", path.display())))
}

fn not_found(path: &Path) -> Error {
    Error::Core(twosecret_core::Error::FolderNotFound(path.display().to_string()))
}

// ---------------------------------------------------------------------------
// Reading and writing a vault folder
// ---------------------------------------------------------------------------

/// What [`read_folder`] found.
#[derive(Clone, Debug, Default)]
pub struct FolderRead {
    /// `None` when the folder only says where the vault went.
    pub vault: Option<VaultFile>,
    pub snapshot: Snapshot,
    /// Files the storage app has not downloaded yet (iCloud's
    /// `.name.icloud` placeholders): where they will be.
    pub waiting: Vec<PathBuf>,
}

#[derive(Clone)]
enum Parsed {
    Item(ItemFile),
    Meta(MetaFile),
}

/// A file read before: when it was changed, its size, what it holds.
type Cached = (SystemTime, u64, Parsed);

/// Files read before, by path: unchanged files are not read again.
static CACHE: Mutex<Option<HashMap<PathBuf, Cached>>> = Mutex::new(None);

fn read_cached(path: &Path, item: bool) -> Option<Parsed> {
    let meta = fs::metadata(path).ok()?;
    let stamp = (meta.modified().ok()?, meta.len());
    if let Some((t, len, parsed)) = CACHE.lock().ok()?.as_ref().and_then(|c| c.get(path)) {
        if (*t, *len) == stamp {
            return Some(parsed.clone());
        }
    }
    let json = fs::read_to_string(path).ok()?;
    let parsed = if item {
        Parsed::Item(serde_json::from_str(&json).ok()?)
    } else {
        Parsed::Meta(serde_json::from_str(&json).ok()?)
    };
    if let Ok(mut cache) = CACHE.lock() {
        cache.get_or_insert_with(HashMap::new).insert(path.to_path_buf(), (stamp.0, stamp.1, parsed.clone()));
    }
    Some(parsed)
}

/// An iCloud placeholder (`.name.icloud`): the file it stands for.
fn icloud_placeholder(dir: &Path, name: &str) -> Option<PathBuf> {
    let real = name.strip_prefix('.')?.strip_suffix(".icloud")?;
    Some(dir.join(real))
}

/// Read everything in a vault's folder (blocking).
pub fn read_folder(dir: &Path) -> Result<FolderRead> {
    if !dir.is_dir() {
        return Err(not_found(dir));
    }
    let mut out = FolderRead::default();
    let moved_path = dir.join(MOVED_FILE);
    if moved_path.exists() {
        out.snapshot.moved = fs::read_to_string(&moved_path).ok().and_then(|j| serde_json::from_str(&j).ok());
        if out.snapshot.moved.is_none() {
            out.snapshot.unreadable += 1;
        }
    }
    let vault_path = dir.join(VAULT_FILE);
    match fs::read_to_string(&vault_path) {
        Ok(json) => out.vault = Some(VaultFile::parse(&json)?),
        Err(_) if dir.join(format!(".{VAULT_FILE}.icloud")).exists() => {
            out.waiting.push(vault_path);
            request_downloads(&out.waiting);
            return Err(Error::Core(twosecret_core::Error::FolderNotFound(format!(
                "{} (still downloading)",
                dir.display()
            ))));
        }
        Err(_) if out.snapshot.moved.is_some() => {}
        Err(_) => return Err(not_found(dir)),
    }

    let entries = fs::read_dir(dir).map_err(|e| io_error(dir, e))?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(real) = icloud_placeholder(dir, &name) {
            out.waiting.push(real);
            continue;
        }
        remove_stale_temp(&entry.path(), &name);
        if !name.starts_with("meta~") || format::parse_file_name(&name).is_none() {
            continue;
        }
        match read_cached(&entry.path(), false) {
            Some(Parsed::Meta(m)) => out.snapshot.metas.push((name, m)),
            _ => out.snapshot.unreadable += 1,
        }
    }

    let items = dir.join(ITEMS_DIR);
    if let Ok(entries) = fs::read_dir(&items) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(real) = icloud_placeholder(&items, &name) {
                out.waiting.push(real);
                continue;
            }
            remove_stale_temp(&entry.path(), &name);
            if format::parse_file_name(&name).is_none() {
                continue;
            }
            match read_cached(&entry.path(), true) {
                Some(Parsed::Item(f)) => out.snapshot.items.push((name, f)),
                _ => out.snapshot.unreadable += 1,
            }
        }
    }
    out.snapshot.items.sort_by(|a, b| a.0.cmp(&b.0));
    out.snapshot.metas.sort_by(|a, b| a.0.cmp(&b.0));
    request_downloads(&out.waiting);
    Ok(out)
}

/// A temporary file left by a write that never finished (older than a day).
fn remove_stale_temp(path: &Path, name: &str) {
    if !name.starts_with(TEMP_PREFIX) {
        return;
    }
    let old = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age.as_secs() > 86_400);
    if old {
        let _ = fs::remove_file(path);
    }
}

/// Ask iCloud Drive to download files it only has placeholders for.
fn request_downloads(paths: &[PathBuf]) {
    #[cfg(target_os = "macos")]
    for path in paths.iter().take(64) {
        let _ = std::process::Command::new("/usr/bin/brctl")
            .arg("download")
            .arg(path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
    #[cfg(not(target_os = "macos"))]
    let _ = paths;
}

/// The path of `rel` (`a/b.json`) inside `dir`, refusing anything that could
/// leave it.
fn inside(dir: &Path, rel: &str) -> Result<PathBuf> {
    let rel_path = Path::new(rel);
    if rel.is_empty() || rel_path.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(Error::Core(twosecret_core::Error::invalid(format!("unexpected file name {rel}"))));
    }
    Ok(dir.join(rel_path))
}

/// Write a file atomically: a temporary file next to it, then a rename.
fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    let parent = path.parent().ok_or_else(|| not_found(path))?;
    fs::create_dir_all(parent).map_err(|e| io_error(parent, e))?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let suffix: String = twosecret_core::util::new_id().chars().take(8).collect();
    let tmp = parent.join(format!("{TEMP_PREFIX}{suffix}-{name}"));
    let result = (|| {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(io_error(path, e));
    }
    Ok(())
}

/// Write and remove the files of a plan (blocking).
pub fn write_plan(dir: &Path, write: &[(String, String)], remove: &[String]) -> Result<()> {
    if !dir.is_dir() {
        return Err(not_found(dir));
    }
    for (rel, contents) in write {
        write_atomic(&inside(dir, rel)?, contents)?;
    }
    for rel in remove {
        match fs::remove_file(inside(dir, rel)?) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_error(&dir.join(rel), e)),
        }
    }
    Ok(())
}

/// Remove a vault's items and names from its folder, keeping a `moved.json`
/// that says where it went (blocking). `vault.json` goes too when the vault
/// was deleted.
fn clear_folder(dir: &Path, moved_json: &str, deleted: bool) -> Result<()> {
    write_atomic(&dir.join(MOVED_FILE), moved_json)?;
    if let Ok(entries) = fs::read_dir(dir.join(ITEMS_DIR)) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".json") || name.ends_with(".icloud") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    let _ = fs::remove_dir(dir.join(ITEMS_DIR));
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("meta~") || (deleted && name == VAULT_FILE) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Where the storage apps keep their folders
// ---------------------------------------------------------------------------

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from)
}

fn home() -> Option<PathBuf> {
    env_path("HOME").or_else(|| env_path("USERPROFILE"))
}

/// Dropbox's folders, from its `info.json`.
fn dropbox_from_info(info: &Path) -> Vec<PathBuf> {
    let Ok(json) = fs::read_to_string(info) else { return Vec::new() };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&json) else { return Vec::new() };
    ["personal", "business"].iter().filter_map(|k| value.get(k)?.get("path")?.as_str().map(PathBuf::from)).collect()
}

/// The folders of the storage apps installed on this device, as (service,
/// folder). Vault folders are found again on other devices by their path
/// inside these.
pub fn service_roots() -> Vec<(FolderService, PathBuf)> {
    let mut out: Vec<(FolderService, PathBuf)> = Vec::new();
    let mut add = |service: FolderService, path: PathBuf| {
        if path.is_dir() && !out.iter().any(|(_, p)| p == &path) {
            out.push((service, path));
        }
    };
    let Some(home) = home() else { return out };
    if cfg!(target_os = "macos") {
        add(FolderService::ICloudDrive, home.join("Library/Mobile Documents/com~apple~CloudDocs"));
        if let Ok(entries) = fs::read_dir(home.join("Library/CloudStorage")) {
            let mut entries: Vec<_> = entries.flatten().map(|e| e.path()).collect();
            entries.sort();
            for path in entries {
                let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                if name.starts_with("Dropbox") {
                    add(FolderService::Dropbox, path);
                } else if name.starts_with("GoogleDrive") {
                    add(FolderService::GoogleDrive, path);
                } else if name.starts_with("OneDrive") {
                    add(FolderService::OneDrive, path);
                }
            }
        }
    }
    if cfg!(windows) {
        add(FolderService::ICloudDrive, home.join("iCloudDrive"));
        for var in ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"] {
            if let Some(path) = env_path(var) {
                add(FolderService::OneDrive, path);
            }
        }
        for var in ["LOCALAPPDATA", "APPDATA"] {
            if let Some(base) = env_path(var) {
                for path in dropbox_from_info(&base.join("Dropbox/info.json")) {
                    add(FolderService::Dropbox, path);
                }
            }
        }
        // Google Drive for desktop: a drive, G: unless chosen otherwise.
        add(FolderService::GoogleDrive, PathBuf::from("G:\\"));
    }
    if !cfg!(windows) {
        for path in dropbox_from_info(&home.join(".dropbox/info.json")) {
            add(FolderService::Dropbox, path);
        }
    }
    add(FolderService::Dropbox, home.join("Dropbox"));
    out.retain(|(s, p)| *s != FolderService::GoogleDrive || !cfg!(windows) || p.join("My Drive").is_dir());
    out
}

/// The folder to suggest for a service on this device.
pub fn suggested_folder(service: FolderService) -> Option<PathBuf> {
    let (_, root) = service_roots().into_iter().find(|(s, _)| *s == service)?;
    // Google Drive keeps the user's own files in "My Drive".
    let my_drive = root.join("My Drive");
    Some(if service == FolderService::GoogleDrive && my_drive.is_dir() { my_drive } else { root })
}

/// The service whose folder holds `path`, if one is recognised.
pub fn service_of(path: &Path) -> Option<FolderService> {
    service_roots().into_iter().find(|(_, root)| path.starts_with(root)).map(|(s, _)| s)
}

/// How other devices can find a vault folder: its path inside the service's
/// folder, else its name.
fn relative_to_service(service: FolderService, path: &Path) -> String {
    let rel = service_roots()
        .into_iter()
        .filter(|(s, _)| *s == service)
        .find_map(|(_, root)| path.strip_prefix(&root).ok().map(|p| p.to_path_buf()));
    let rel = rel.unwrap_or_else(|| path.file_name().map(PathBuf::from).unwrap_or_default());
    rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/")
}

/// Where a vault folder another device moved a vault to is on this device.
fn locate(service: FolderService, folder: &str) -> Option<PathBuf> {
    if folder.is_empty() || folder.split('/').any(|p| p.is_empty() || p == "." || p == "..") {
        return None;
    }
    service_roots()
        .into_iter()
        .filter(|(s, _)| *s == service)
        .map(|(_, root)| folder.split('/').fold(root, |p, part| p.join(part)))
        .find(|p| p.join(VAULT_FILE).is_file())
}

/// The vault folder for a new vault in `parent`: `<parent>/2Secret/<name>-<id>`
/// (without the extra `2Secret` when `parent` is already called that).
pub fn vault_dir(parent: &Path, name: &str, vault_id: &str) -> PathBuf {
    let base = if parent.file_name().is_some_and(|n| n == PARENT_DIR) {
        parent.to_path_buf()
    } else {
        parent.join(PARENT_DIR)
    };
    base.join(format::vault_dir_name(name, vault_id))
}

/// Vault folders in `dir`: `dir` itself, or the ones in it (also in a
/// `2Secret` folder in it).
pub fn find_vault_dirs(dir: &Path) -> Vec<PathBuf> {
    if dir.join(VAULT_FILE).is_file() || dir.join(MOVED_FILE).is_file() {
        return vec![dir.to_path_buf()];
    }
    let mut out = Vec::new();
    for base in [dir.to_path_buf(), dir.join(PARENT_DIR)] {
        if let Ok(entries) = fs::read_dir(&base) {
            for entry in entries.flatten() {
                if entry.path().join(VAULT_FILE).is_file() {
                    out.push(entry.path());
                }
            }
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Where a vault's files are
// ---------------------------------------------------------------------------

/// Where a vault's files are: a folder on this device or on a WebDAV server.
#[derive(Clone, Debug)]
pub enum Store {
    Local(PathBuf),
    Dav(Dav),
}

fn dav_not_found(d: &Dav) -> Error {
    Error::Core(twosecret_core::Error::FolderNotFound(d.url().to_string()))
}

impl Store {
    /// The files of a vault kept in a folder.
    pub fn of(session: &Session, vault_id: &str) -> Result<Store> {
        let rec = session
            .profile()
            .vault(vault_id)
            .ok_or_else(|| twosecret_core::Error::not_found(format!("vault {vault_id}")))?;
        match &rec.location {
            VaultLocation::Folder { path, .. } => Ok(Store::Local(PathBuf::from(path))),
            VaultLocation::WebDav { url, user, password } => {
                let password = session.open_webdav_password(vault_id, password)?;
                Ok(Store::Dav(Dav::new(url, user, &password)?))
            }
            _ => Err(twosecret_core::Error::invalid("this vault is not kept in a folder").into()),
        }
    }

    /// Read everything in the folder.
    pub async fn read(&self) -> Result<FolderRead> {
        match self {
            Store::Local(dir) => {
                let dir = dir.clone();
                blocking(move || read_folder(&dir)).await?
            }
            Store::Dav(d) => read_dav(d).await,
        }
    }

    /// Write and remove files (paths relative to the folder).
    pub async fn write(&self, write: Vec<(String, String)>, remove: Vec<String>) -> Result<()> {
        match self {
            Store::Local(dir) => {
                let dir = dir.clone();
                blocking(move || write_plan(&dir, &write, &remove)).await?
            }
            Store::Dav(d) => {
                if write.iter().any(|(p, _)| p.starts_with(ITEMS_DIR)) {
                    d.mkcol(&format!("{ITEMS_DIR}/")).await?;
                }
                let puts: Vec<Result<()>> = stream::iter(write.iter())
                    .map(|(path, contents)| d.put(path, contents))
                    .buffer_unordered(6)
                    .collect()
                    .await;
                puts.into_iter().collect::<Result<Vec<()>>>()?;
                for path in &remove {
                    d.delete(path).await?;
                }
                Ok(())
            }
        }
    }

    /// Make the folder (its parent must exist, or be made on this device).
    async fn create(&self) -> Result<()> {
        match self {
            Store::Local(dir) => {
                let dir = dir.clone();
                blocking(move || fs::create_dir_all(&dir).map_err(|e| io_error(&dir, e))).await?
            }
            Store::Dav(d) => d.mkcol("").await,
        }
    }

    /// Remove the folder and everything in it (a copy that failed).
    async fn remove_all(&self) {
        match self {
            Store::Local(dir) => {
                let dir = dir.clone();
                let _ = blocking(move || fs::remove_dir_all(dir)).await;
            }
            Store::Dav(d) => {
                let _ = d.delete("").await;
            }
        }
    }

    /// Clear the folder of a vault that moved away, leaving `moved.json`.
    async fn clear(&self, moved_json: String, deleted: bool) -> Result<()> {
        match self {
            Store::Local(dir) => {
                let dir = dir.clone();
                blocking(move || if dir.is_dir() { clear_folder(&dir, &moved_json, deleted) } else { Ok(()) }).await?
            }
            Store::Dav(d) => {
                let Some(entries) = d.list("").await? else { return Ok(()) };
                d.put(MOVED_FILE, &moved_json).await?;
                if let Some(items) = d.list(&format!("{ITEMS_DIR}/")).await? {
                    for e in items.iter().filter(|e| !e.dir) {
                        d.delete(&format!("{ITEMS_DIR}/{}", e.name)).await?;
                    }
                    d.delete(&format!("{ITEMS_DIR}/")).await?;
                }
                for e in entries.iter().filter(|e| !e.dir) {
                    if e.name.starts_with("meta~") || (deleted && e.name == VAULT_FILE) {
                        d.delete(&e.name).await?;
                    }
                }
                Ok(())
            }
        }
    }
}

/// Read a vault folder on a WebDAV server: what changed since the last time
/// is fetched, a few files at a time.
async fn read_dav(d: &Dav) -> Result<FolderRead> {
    let Some(entries) = d.list("").await? else { return Err(dav_not_found(d)) };
    let mut out = FolderRead::default();
    let tag = |name: &str| entries.iter().find(|e| !e.dir && e.name == name).map(|e| e.tag.clone());
    if let Some(t) = tag(MOVED_FILE) {
        out.snapshot.moved = d.get(MOVED_FILE, Some(&t)).await?.and_then(|j| serde_json::from_str(&j).ok());
        if out.snapshot.moved.is_none() {
            out.snapshot.unreadable += 1;
        }
    }
    match tag(VAULT_FILE) {
        Some(t) => {
            let json = d.get(VAULT_FILE, Some(&t)).await?.ok_or_else(|| dav_not_found(d))?;
            out.vault = Some(VaultFile::parse(&json)?);
        }
        None if out.snapshot.moved.is_some() => {}
        None => return Err(dav_not_found(d)),
    }
    let metas: Vec<(String, String)> = entries
        .iter()
        .filter(|e| !e.dir && e.name.starts_with("meta~") && format::parse_file_name(&e.name).is_some())
        .map(|e| (e.name.clone(), e.tag.clone()))
        .collect();
    for (name, json) in fetch_all(d, "", metas).await? {
        match json.and_then(|j| serde_json::from_str::<MetaFile>(&j).ok()) {
            Some(m) => out.snapshot.metas.push((name, m)),
            None => out.snapshot.unreadable += 1,
        }
    }
    if entries.iter().any(|e| e.dir && e.name == ITEMS_DIR) {
        let items: Vec<(String, String)> = d
            .list(&format!("{ITEMS_DIR}/"))
            .await?
            .unwrap_or_default()
            .into_iter()
            .filter(|e| !e.dir && format::parse_file_name(&e.name).is_some())
            .map(|e| (e.name, e.tag))
            .collect();
        for (name, json) in fetch_all(d, &format!("{ITEMS_DIR}/"), items).await? {
            match json.and_then(|j| serde_json::from_str::<ItemFile>(&j).ok()) {
                Some(f) => out.snapshot.items.push((name, f)),
                None => out.snapshot.unreadable += 1,
            }
        }
    }
    out.snapshot.items.sort_by(|a, b| a.0.cmp(&b.0));
    out.snapshot.metas.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Fetch files of a WebDAV folder side by side. A file gone meanwhile is
/// `None`.
async fn fetch_all(d: &Dav, dir: &str, files: Vec<(String, String)>) -> Result<Vec<(String, Option<String>)>> {
    let results: Vec<Result<(String, Option<String>)>> = stream::iter(files)
        .map(|(name, tag)| async move {
            let json = d.get(&format!("{dir}{name}"), Some(&tag)).await?;
            Ok((name, json))
        })
        .buffer_unordered(8)
        .collect()
        .await;
    results.into_iter().collect()
}

/// Reach a WebDAV folder, also from the address of a Nextcloud or ownCloud
/// server alone (whose files are at `remote.php/dav/files/<user>/`).
pub async fn connect_webdav(url: &str, user: &str, password: &str) -> Result<Dav> {
    let d = Dav::new(url, user, password)?;
    if d.check().await? {
        return Ok(d);
    }
    let nextcloud = d.join(&format!("remote.php/dav/files/{user}/"));
    if nextcloud.check().await? {
        return Ok(nextcloud);
    }
    Err(Error::Api {
        status: 404,
        code: "webdav_not_found".into(),
        message: "there is no WebDAV folder at this address".into(),
    })
}

/// The vault folders in a WebDAV folder: the folder itself, or the ones in it
/// (also in a `2Secret` folder in it).
async fn find_vault_dirs_dav(d: &Dav) -> Result<Vec<Dav>> {
    let Some(entries) = d.list("").await? else { return Ok(Vec::new()) };
    if entries.iter().any(|e| !e.dir && (e.name == VAULT_FILE || e.name == MOVED_FILE)) {
        return Ok(vec![d.clone()]);
    }
    let mut out = Vec::new();
    for base in [d.clone(), d.join(&format!("{PARENT_DIR}/"))] {
        let Some(entries) = base.list("").await? else { continue };
        for e in entries.iter().filter(|e| e.dir) {
            let sub = base.join(&format!("{}/", e.name));
            if sub.list("").await?.is_some_and(|l| l.iter().any(|f| !f.dir && f.name == VAULT_FILE)) {
                out.push(sub);
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Syncing
// ---------------------------------------------------------------------------

/// The result of syncing one vault folder.
#[derive(Debug)]
pub struct FolderOutcome {
    pub vault_id: String,
    pub result: Result<FolderReport>,
    /// Files the storage app is still downloading.
    pub waiting: usize,
}

impl FolderOutcome {
    /// The folder is not there (or not yet downloaded).
    pub fn not_found(&self) -> bool {
        matches!(&self.result, Err(Error::Core(twosecret_core::Error::FolderNotFound(_))))
    }
}

/// Sync one vault in a storage folder (see [`sync_folders_with`]).
pub async fn sync_folder(session: &mut Session, vault_id: &str) -> Result<FolderReport> {
    let mut access = session;
    sync_folder_with(&mut access, vault_id).await.0
}

async fn sync_folder_with<A: SessionAccess>(access: &mut A, vault_id: &str) -> (Result<FolderReport>, usize) {
    let store = match access.with_session(|s| Store::of(s, vault_id)) {
        Ok(Ok(store)) => store,
        Ok(Err(e)) | Err(e) => return (Err(e), 0),
    };
    let read = match store.read().await {
        Ok(read) => read,
        Err(e) => return (Err(e), 0),
    };
    let waiting = read.waiting.len();
    (sync_read(access, vault_id, &store, read).await, waiting)
}

async fn sync_read<A: SessionAccess>(
    access: &mut A,
    vault_id: &str,
    store: &Store,
    read: FolderRead,
) -> Result<FolderReport> {
    let id = vault_id.to_string();
    let plan: FolderPlan = access.with_session(|s| -> Result<FolderPlan> {
        if let Some(file) = &read.vault {
            s.check_vault_file(&id, file)?;
        }
        Ok(s.apply_folder(&id, &read.snapshot)?)
    })??;
    // Moved away: what the folder still had is merged in above; nothing more
    // goes into it.
    if let Some(moved) = &plan.report.moved {
        follow_move(access, vault_id, moved).await?;
        return Ok(FolderReport { written: 0, ..plan.report });
    }
    store.write(plan.write.clone(), plan.remove.clone()).await?;
    access.with_session(|s| s.folder_written(&plan))?;
    Ok(plan.report)
}

/// Another device moved the vault out of its folder: follow it.
async fn follow_move<A: SessionAccess>(access: &mut A, vault_id: &str, moved: &MovedTo) -> Result<()> {
    let id = vault_id.to_string();
    match &moved.to {
        MoveTarget::Account => {
            access.with_session(|s| s.relocate_vault(&id, VaultLocation::Account))??;
        }
        MoveTarget::Device | MoveTarget::Deleted => access.with_session(|s| s.forget_folder_vault(&id))?,
        MoveTarget::Folder { service, folder } => {
            let (service, folder) = (*service, folder.clone());
            if let Some(path) = blocking(move || locate(service, &folder)).await? {
                let location = VaultLocation::Folder { path: path.to_string_lossy().into_owned(), service };
                access.with_session(|s| s.set_vault_folder(&id, location))??;
            }
        }
        MoveTarget::WebDav { url, user, password } => {
            let location = VaultLocation::WebDav { url: url.clone(), user: user.clone(), password: password.clone() };
            access.with_session(|s| s.set_vault_folder(&id, location))??;
        }
    }
    Ok(())
}

/// Sync every vault kept in a folder (on this device or a WebDAV server),
/// each on its own: a folder that is missing does not stop the others.
/// Server placeholders of vaults that moved to a folder this device can
/// reach are taken from there first.
pub async fn sync_folders_with<A: SessionAccess>(access: &mut A) -> Result<Vec<FolderOutcome>> {
    attach_moved_with(access).await?;
    let ids: Vec<String> = access.with_session(|s| {
        s.profile().vaults.iter().filter(|v| v.location.is_folder()).map(|v| v.id.clone()).collect()
    })?;
    let mut out = Vec::new();
    for id in ids {
        let (result, waiting) = sync_folder_with(access, &id).await;
        out.push(FolderOutcome { vault_id: id, result, waiting });
    }
    Ok(out)
}

/// Sync every vault in a folder (see [`sync_folders_with`]).
pub async fn sync_folders(session: &mut Session) -> Result<Vec<FolderOutcome>> {
    let mut access = session;
    sync_folders_with(&mut access).await
}

/// Take vaults that another device moved from the server to a folder from
/// that folder, when this device can reach it (a storage app's folder it
/// has, or the WebDAV server). Returns their ids.
pub async fn attach_moved_with<A: SessionAccess>(access: &mut A) -> Result<Vec<String>> {
    let moved: Vec<(String, MoveTarget)> = access.with_session(|s| {
        s.vaults().into_iter().filter(|v| v.is_placeholder()).filter_map(|v| Some((v.id, v.moved?.to))).collect()
    })?;
    let mut attached = Vec::new();
    for (id, target) in moved {
        let (store, location) = match target {
            MoveTarget::Folder { service, folder } => {
                let Some(dir) = blocking(move || locate(service, &folder)).await? else { continue };
                let location = VaultLocation::Folder { path: dir.to_string_lossy().into_owned(), service };
                (Store::Local(dir), location)
            }
            MoveTarget::WebDav { url, user, password } => {
                let Ok(Ok(pw)) = access.with_session(|s| s.open_webdav_password(&id, &password)) else { continue };
                let Ok(d) = Dav::new(&url, &user, &pw) else { continue };
                (Store::Dav(d), VaultLocation::WebDav { url, user, password })
            }
            _ => continue,
        };
        let Ok(read) = store.read().await else { continue };
        let (Some(file), None) = (&read.vault, &read.snapshot.moved) else { continue };
        if file.vault_id != id {
            continue;
        }
        let ok = access.with_session(|s| s.attach_folder(file, &read.snapshot, location).is_ok())?;
        if ok {
            let _ = sync_read(access, &id, &store, read).await;
            attached.push(id);
        }
    }
    Ok(attached)
}

// ---------------------------------------------------------------------------
// Creating, adding, moving and deleting folder vaults
// ---------------------------------------------------------------------------

/// Where to keep or move a vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MoveTo {
    /// With the account: on its server (or, for an account without one, on
    /// this device, going along to a server later).
    Account,
    /// Only this device.
    Device,
    /// A storage app's folder: the vault gets a folder in `<parent>/2Secret`.
    Folder { parent: PathBuf, service: FolderService },
    /// A WebDAV server: the vault gets a folder in `<url>/2Secret`. `url` may
    /// also be just the address of a Nextcloud or ownCloud server.
    WebDav { url: String, user: String, password: String },
}

/// Make the folder for vault `vault_id` at `to` (a folder or WebDAV target):
/// its files' place, its location and how other devices find it.
async fn prepare_target(session: &Session, vault_id: &str, to: &MoveTo) -> Result<(Store, VaultLocation, MoveTarget)> {
    let name = session.vault(vault_id).map(|v| v.name).unwrap_or_default();
    match to {
        MoveTo::Folder { parent, service } => {
            if !parent.is_dir() {
                return Err(not_found(parent));
            }
            let dir = vault_dir(parent, &name, vault_id);
            let folder = relative_to_service(*service, &dir);
            let store = Store::Local(dir.clone());
            store.create().await?;
            let location = VaultLocation::Folder { path: dir.to_string_lossy().into_owned(), service: *service };
            Ok((store, location, MoveTarget::Folder { service: *service, folder }))
        }
        MoveTo::WebDav { url, user, password } => {
            let base = connect_webdav(url, user, password).await?;
            let parent = if base.url().trim_end_matches('/').ends_with(&format!("/{PARENT_DIR}")) {
                base
            } else {
                let parent = base.join(&format!("{PARENT_DIR}/"));
                base.mkcol(&format!("{PARENT_DIR}/")).await?;
                parent
            };
            let dir = parent.join(&format!("{}/", format::vault_dir_name(&name, vault_id)));
            let store = Store::Dav(dir.clone());
            store.create().await?;
            let sealed = session.seal_webdav_password(vault_id, password)?;
            let location =
                VaultLocation::WebDav { url: dir.url().to_string(), user: user.clone(), password: sealed.clone() };
            let target = MoveTarget::WebDav { url: dir.url().to_string(), user: user.clone(), password: sealed };
            Ok((store, location, target))
        }
        _ => Err(twosecret_core::Error::invalid("not a folder").into()),
    }
}

/// Write all of a vault's files to `store` and check that they arrived and
/// open. Refuses a folder that holds another vault.
async fn copy_to(session: &mut Session, vault_id: &str, store: &Store) -> Result<()> {
    if let Ok(existing) = store.read().await {
        if existing.vault.as_ref().is_some_and(|v| v.vault_id != vault_id) {
            return Err(twosecret_core::Error::invalid("that folder holds another vault").into());
        }
    }
    let files = session.folder_export(vault_id)?;
    let expected = files.iter().filter(|(p, _)| p.starts_with(ITEMS_DIR)).count();
    store.write(files, vec![MOVED_FILE.to_string()]).await?;
    let read = store.read().await?;
    let file = read.vault.as_ref().ok_or_else(|| twosecret_core::Error::Storage("vault.json did not arrive".into()))?;
    session.check_vault_file(vault_id, file)?;
    let readable = read.snapshot.items.iter().filter(|(_, f)| f.data.is_some()).count();
    if readable < expected || read.snapshot.unreadable > 0 {
        return Err(twosecret_core::Error::Storage("the copy in the folder is incomplete".into()).into());
    }
    Ok(())
}

/// Create a vault in a storage app's folder: in `<parent>/2Secret/<name>-<id>`.
pub async fn create_folder_vault(
    session: &mut Session,
    name: &str,
    description: &str,
    parent: &Path,
    service: FolderService,
) -> Result<String> {
    create_vault_in(session, name, description, &MoveTo::Folder { parent: parent.to_path_buf(), service }).await
}

/// Create a vault in a folder (a storage app's or a WebDAV server's).
pub async fn create_vault_in(session: &mut Session, name: &str, description: &str, to: &MoveTo) -> Result<String> {
    let placeholder = VaultLocation::Folder { path: String::new(), service: FolderService::Other };
    let id = session.create_vault_at(name, description, placeholder)?;
    let result: Result<()> = async {
        let (store, location, _) = prepare_target(session, &id, to).await?;
        session.set_vault_folder(&id, location)?;
        let files = session.folder_export(&id)?;
        store.write(files, Vec::new()).await?;
        sync_folder(session, &id).await.map(|_| ())
    }
    .await;
    if let Err(e) = result {
        let _ = session.delete_vault(&id);
        return Err(e);
    }
    Ok(id)
}

/// Add a vault that is in a storage app's folder (made on another device),
/// or take a vault this device knows as a server placeholder from its
/// folder. `dir` is the vault's folder or a folder holding one vault folder.
pub async fn attach_folder(session: &mut Session, dir: &Path, service: Option<FolderService>) -> Result<String> {
    let found_in = dir.to_path_buf();
    let dirs = blocking(move || find_vault_dirs(&found_in)).await?;
    let dir = one_vault(dirs, &dir.display().to_string(), |d| d.file_name().map(|n| n.to_string_lossy().into_owned()))?;
    let service = match service {
        Some(s) => s,
        None => {
            let probe = dir.clone();
            blocking(move || service_of(&probe)).await?.unwrap_or_default()
        }
    };
    let location = VaultLocation::Folder { path: dir.to_string_lossy().into_owned(), service };
    attach_store(session, Store::Local(dir), |_, _| Ok(location)).await
}

/// Add a vault that is on a WebDAV server (made on another device). `url` is
/// the vault's folder, a folder holding one, or the server's address.
pub async fn attach_webdav(session: &mut Session, url: &str, user: &str, password: &str) -> Result<String> {
    let base = connect_webdav(url, user, password).await?;
    let dirs = find_vault_dirs_dav(&base).await?;
    let dir = one_vault(dirs, base.url(), |d| d.url().trim_end_matches('/').rsplit('/').next().map(String::from))?;
    let (user, password) = (user.to_string(), password.to_string());
    let url = dir.url().to_string();
    attach_store(session, Store::Dav(dir), move |s, file| {
        Ok(VaultLocation::WebDav { url, user, password: s.seal_webdav_password_with(file, &password)? })
    })
    .await
}

fn one_vault<T>(mut found: Vec<T>, place: &str, name: impl Fn(&T) -> Option<String>) -> Result<T> {
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(twosecret_core::Error::invalid(format!("there is no 2Secret vault in {place}")).into()),
        _ => {
            let names: Vec<String> = found.iter().filter_map(name).collect();
            Err(twosecret_core::Error::invalid(format!(
                "there are several vaults in this folder; choose one of: {}",
                names.join(", ")
            ))
            .into())
        }
    }
}

async fn attach_store(
    session: &mut Session,
    store: Store,
    location: impl FnOnce(&Session, &VaultFile) -> twosecret_core::Result<VaultLocation>,
) -> Result<String> {
    let read = store.read().await?;
    if let Some(moved) = &read.snapshot.moved {
        let to = match &read.vault {
            Some(file) => session.read_moved_with(file, moved),
            None => Err(twosecret_core::Error::Decryption),
        };
        return Err(match to {
            Ok(to) => twosecret_core::Error::invalid(format!("this vault moved to {}", to.to)),
            Err(_) => twosecret_core::Error::invalid("this folder no longer holds a vault (it moved or was deleted)"),
        }
        .into());
    }
    let file = read.vault.clone().ok_or_else(|| twosecret_core::Error::invalid("this folder holds no vault"))?;
    let location = location(session, &file)?;
    let id = session.attach_folder(&file, &read.snapshot, location)?;
    let mut access = &mut *session;
    sync_read(&mut access, &id, &store, read).await?;
    Ok(id)
}

/// Move a vault between the server, this device and folders. Its contents
/// are copied and checked before anything is removed, and the vault keeps
/// its id and key, so other devices of the account follow it.
pub async fn move_vault(session: &mut Session, vault_id: &str, to: MoveTo) -> Result<()> {
    session.can_move(vault_id)?;
    let rec = session
        .profile()
        .vault(vault_id)
        .cloned()
        .ok_or_else(|| twosecret_core::Error::not_found(format!("vault {vault_id}")))?;
    let linked = session.server().is_some();
    let from = rec.location.clone();
    let old_store = if from.is_folder() { Some(Store::of(session, vault_id)?) } else { None };

    // Up to date first, wherever it is now.
    match &from {
        VaultLocation::Account if linked => {
            sync(session).await?;
        }
        VaultLocation::Folder { .. } | VaultLocation::WebDav { .. } => match sync_folder(session, vault_id).await {
            Ok(_) => {}
            // The folder is gone: move what this device has.
            Err(Error::Core(twosecret_core::Error::FolderNotFound(_))) => {}
            Err(e) => return Err(e),
        },
        _ => {}
    }
    session.can_move(vault_id)?;
    let on_server = match &from {
        VaultLocation::Account => {
            linked && session.profile().vault(vault_id).is_some_and(|v| v.sync_state == SyncState::Synced)
        }
        VaultLocation::Folder { .. } | VaultLocation::WebDav { .. } => linked && rec.on_server,
        VaultLocation::Device => false,
    };

    let (location, target, new_store) = match &to {
        MoveTo::Account => (VaultLocation::Account, MoveTarget::Account, None),
        MoveTo::Device => (VaultLocation::Device, MoveTarget::Device, None),
        MoveTo::Folder { .. } | MoveTo::WebDav { .. } => {
            let (store, location, target) = prepare_target(session, vault_id, &to).await?;
            let same = match (&from, &location) {
                (VaultLocation::Folder { path: a, .. }, VaultLocation::Folder { path: b, .. }) => a == b,
                (VaultLocation::WebDav { url: a, .. }, VaultLocation::WebDav { url: b, .. }) => a == b,
                _ => false,
            };
            if same {
                return Ok(());
            }
            if let Err(e) = copy_to(session, vault_id, &store).await {
                store.remove_all().await;
                return Err(e);
            }
            (location, target, Some(store))
        }
    };
    let moved = MovedTo { to: target.clone(), at: now() };

    // The server: mark its copy as a placeholder before leaving it, so the
    // other devices stop adding to it (or tell them where it went now).
    if on_server && matches!(target, MoveTarget::Folder { .. } | MoveTarget::WebDav { .. }) {
        let client = client_for(session)?;
        let meta = session.placeholder_meta(vault_id, Some(moved.clone()))?;
        let key_rev = session.profile().vault(vault_id).map(|v| v.key_rev);
        if let Err(e) = client.update_vault(vault_id, &UpdateVaultRequest { meta, key_rev }).await {
            if let Some(store) = &new_store {
                store.remove_all().await;
            }
            return Err(e);
        }
    }

    session.relocate_vault(vault_id, location)?;

    // Leave the old place.
    if let Some(store) = old_store {
        let moved_json = session.moved_file(vault_id, &moved)?;
        let _ = store.clear(moved_json, false).await;
    }
    if linked {
        match &target {
            // The server copy goes when the vault stays on one device.
            MoveTarget::Device if on_server => {
                let client = client_for(session)?;
                match client.delete_vault(vault_id).await {
                    Ok(()) => {}
                    Err(e) if e.is_not_found() => {}
                    // Tried again with the next sync.
                    Err(_) => {}
                }
            }
            // Takes what is left on the placeholder, or uploads everything.
            _ => {
                if let Err(e) = sync(session).await {
                    if target == MoveTarget::Account {
                        return Err(e);
                    }
                }
            }
        }
    }
    if session.profile().vault(vault_id).is_some_and(|v| v.location.is_folder()) {
        sync_folder(session, vault_id).await?;
    }
    Ok(())
}

/// Delete a vault kept in a folder: its files go (a `moved.json` tells the
/// other devices), and so does its server placeholder.
pub async fn delete_folder_vault(session: &mut Session, vault_id: &str) -> Result<()> {
    let rec = session
        .profile()
        .vault(vault_id)
        .cloned()
        .ok_or_else(|| twosecret_core::Error::not_found(format!("vault {vault_id}")))?;
    if let Ok(store) = Store::of(session, vault_id) {
        let moved_json = session.moved_file(vault_id, &MovedTo { to: MoveTarget::Deleted, at: now() })?;
        let _ = store.clear(moved_json, true).await;
    }
    session.delete_vault(vault_id)?;
    if session.server().is_some() && rec.on_server {
        sync(session).await?;
    }
    Ok(())
}
