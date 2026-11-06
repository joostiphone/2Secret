//! Vaults in storage folders (iCloud Drive, Dropbox, Google Drive, OneDrive,
//! Syncthing, a network share): reading and writing their files, finding the
//! storage apps' folders, and moving vaults between the server, this device
//! and folders. The format and the merge rules are in
//! [`twosecret_core::folder`]; `docs/VAULT-FOLDER.md` describes them.
//!
//! A folder is reached through [`FolderFs`]: the file system on desktops
//! ([`LocalFs`]), or a folder the person chose in the system's folder picker
//! on iPhone, iPad and Android (the app provides those, see
//! [`set_picked_folders`]). File access runs on its own thread: opening a
//! file a storage app has not downloaded yet can wait for the network.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::stream::{self, StreamExt};
use twosecret_core::api::UpdateVaultRequest;
use twosecret_core::folder::{
    self as format, FolderPlan, FolderReport, ItemFile, MetaFile, Snapshot, VaultFile, ITEMS_DIR, MOVED_FILE,
    PARENT_DIR, TEMP_PREFIX, VAULT_FILE,
};
use twosecret_core::profile::{FolderGrant, FolderService, MoveTarget, MovedTo, SyncState, VaultLocation};
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

fn fs_error(fs: &dyn FolderFs, e: io::Error) -> Error {
    Error::Core(twosecret_core::Error::Storage(format!("{}: {e}", fs.describe())))
}

fn not_found_at(place: String) -> Error {
    Error::Core(twosecret_core::Error::FolderNotFound(place))
}

fn not_found(path: &Path) -> Error {
    not_found_at(path.display().to_string())
}

// ---------------------------------------------------------------------------
// Reaching a folder's files
// ---------------------------------------------------------------------------

/// One entry of a folder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsEntry {
    pub name: String,
    pub dir: bool,
    /// When it was last changed (milliseconds since 1970, 0 when unknown)
    /// and its size: a file whose stamp did not change is not read again.
    pub stamp: (i64, u64),
}

/// A folder's files, wherever the platform keeps them: on the file system
/// ([`LocalFs`]), or in a folder the system's folder picker gave this app
/// (iPhone, iPad, Android). Paths are relative to the folder, with `/`
/// between names; `""` is the folder itself. The calls block.
pub trait FolderFs: Send + Sync {
    /// Where the folder is, for people (and to tell folders apart).
    fn describe(&self) -> String;
    /// The folder's own name.
    fn name(&self) -> String;
    /// The entries of the folder `dir`; `None` when it is not there.
    fn list(&self, dir: &str) -> io::Result<Option<Vec<FsEntry>>>;
    /// Whether the file `path` is there.
    fn is_file(&self, path: &str) -> bool {
        let (dir, name) = path.rsplit_once('/').unwrap_or(("", path));
        self.list(dir).ok().flatten().is_some_and(|l| l.iter().any(|e| !e.dir && e.name == name))
    }
    /// A file's contents; `None` when it is not there.
    fn read(&self, path: &str) -> io::Result<Option<Vec<u8>>>;
    /// Write a file, making the folders it is in. Atomic where the platform
    /// allows it; elsewhere another device may see a half-written file,
    /// which it skips and reads again later.
    fn write(&self, path: &str, contents: &[u8]) -> io::Result<()>;
    /// Remove a file or an empty folder; one that is not there is fine.
    fn remove(&self, path: &str) -> io::Result<()>;
    /// Make the folder itself (its parent is there).
    fn create(&self) -> io::Result<()>;
    /// Remove the folder and everything in it.
    fn remove_all(&self) -> io::Result<()>;
    /// The folder at `path` inside this one.
    fn child(&self, path: &str) -> Arc<dyn FolderFs>;
    /// Ask the storage app to download files it only has placeholders for.
    fn request_downloads(&self, _paths: &[String]) {}
}

/// Refuse a relative path that could leave the folder.
fn check_rel(rel: &str) -> io::Result<()> {
    let bad = rel.starts_with('/')
        || rel.contains('\\')
        || rel.split('/').any(|p| p.is_empty() || p == "." || p == "..")
        || Path::new(rel).components().any(|c| !matches!(c, Component::Normal(_)));
    if bad && !rel.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unexpected file name {rel}")));
    }
    Ok(())
}

/// `a/b` from `a` and `b` (either may be empty).
fn join_rel(a: &str, b: &str) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, _) => b.to_string(),
        (_, true) => a.to_string(),
        _ => format!("{a}/{b}"),
    }
}

fn millis(t: Option<SystemTime>) -> i64 {
    t.and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map_or(0, |d| d.as_millis() as i64)
}

/// Coordinates file access with the storage apps, on systems that ask for it
/// (iPhone and iPad: `NSFileCoordinator`, which also downloads a file that
/// is still in the cloud before it is read, and tells the storage app what
/// changed).
pub trait Coordinator: Send + Sync {
    /// Run `f` to read `path` (a file or a folder).
    fn read(&self, path: &Path, f: &mut dyn FnMut(&Path) -> io::Result<()>) -> io::Result<()>;
    /// Run `f` to write or replace `path`.
    fn write(&self, path: &Path, f: &mut dyn FnMut(&Path) -> io::Result<()>) -> io::Result<()>;
    /// Run `f` to remove `path`.
    fn remove(&self, path: &Path, f: &mut dyn FnMut(&Path) -> io::Result<()>) -> io::Result<()>;
    /// Ask for files that are still in the cloud to be downloaded.
    fn download(&self, _paths: &[PathBuf]) {}
}

#[derive(Clone, Copy)]
enum Access {
    Read,
    Write,
    Remove,
}

/// A folder on the file system.
#[derive(Clone)]
pub struct LocalFs {
    dir: PathBuf,
    coordinator: Option<Arc<dyn Coordinator>>,
}

impl LocalFs {
    pub fn new(dir: impl Into<PathBuf>) -> LocalFs {
        LocalFs { dir: dir.into(), coordinator: None }
    }

    /// A folder whose files are reached through a [`Coordinator`].
    pub fn coordinated(dir: impl Into<PathBuf>, coordinator: Arc<dyn Coordinator>) -> LocalFs {
        LocalFs { dir: dir.into(), coordinator: Some(coordinator) }
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    fn at(&self, rel: &str) -> io::Result<PathBuf> {
        check_rel(rel)?;
        Ok(rel.split('/').filter(|p| !p.is_empty()).fold(self.dir.clone(), |p, part| p.join(part)))
    }

    fn coordinate<T>(&self, access: Access, path: &Path, f: impl FnOnce(&Path) -> io::Result<T>) -> io::Result<T> {
        let Some(c) = &self.coordinator else { return f(path) };
        let mut f = Some(f);
        let mut out: Option<io::Result<T>> = None;
        let mut run = |p: &Path| -> io::Result<()> {
            if let Some(f) = f.take() {
                out = Some(f(p));
            }
            Ok(())
        };
        match access {
            Access::Read => c.read(path, &mut run),
            Access::Write => c.write(path, &mut run),
            Access::Remove => c.remove(path, &mut run),
        }?;
        out.unwrap_or_else(|| Err(io::Error::other("the storage app gave no access to the file")))
    }
}

/// Write a file atomically: a temporary file next to it, then a rename.
fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    fs::create_dir_all(parent)?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let suffix: String = twosecret_core::util::new_id().chars().take(8).collect();
    let tmp = parent.join(format!("{TEMP_PREFIX}{suffix}-{name}"));
    let result = (|| {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn missing_is_fine(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn gone_is_none<T>(result: io::Result<Option<T>>) -> io::Result<Option<T>> {
    match result {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        other => other,
    }
}

impl FolderFs for LocalFs {
    fn describe(&self) -> String {
        self.dir.display().to_string()
    }

    fn name(&self) -> String {
        self.dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
    }

    fn list(&self, dir: &str) -> io::Result<Option<Vec<FsEntry>>> {
        let path = self.at(dir)?;
        let list = || {
            gone_is_none(self.coordinate(Access::Read, &path, |path| {
                if !path.is_dir() {
                    return Ok(None);
                }
                let mut out = Vec::new();
                for entry in fs::read_dir(path)?.flatten() {
                    let meta = fs::metadata(entry.path()).ok();
                    out.push(FsEntry {
                        name: entry.file_name().to_string_lossy().into_owned(),
                        dir: meta.as_ref().is_some_and(|m| m.is_dir()),
                        stamp: meta.map_or((0, 0), |m| (millis(m.modified().ok()), m.len())),
                    });
                }
                Ok(Some(out))
            }))
        };
        let out = list()?;
        // iOS can list a storage app's folder as empty the first time.
        if self.coordinator.is_some() && out.as_ref().is_some_and(|l| l.is_empty()) {
            std::thread::sleep(std::time::Duration::from_millis(250));
            return list();
        }
        Ok(out)
    }

    fn is_file(&self, path: &str) -> bool {
        self.at(path).is_ok_and(|p| p.is_file())
    }

    fn read(&self, path: &str) -> io::Result<Option<Vec<u8>>> {
        let path = self.at(path)?;
        gone_is_none(self.coordinate(Access::Read, &path, |path| fs::read(path).map(Some)))
    }

    fn write(&self, path: &str, contents: &[u8]) -> io::Result<()> {
        if path.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "no file name"));
        }
        let path = self.at(path)?;
        self.coordinate(Access::Write, &path, |path| write_atomic(path, contents))
    }

    fn remove(&self, path: &str) -> io::Result<()> {
        let path = self.at(path)?;
        missing_is_fine(self.coordinate(Access::Remove, &path, |path| {
            if path.is_dir() {
                fs::remove_dir(path)
            } else {
                fs::remove_file(path)
            }
        }))
    }

    fn create(&self) -> io::Result<()> {
        self.coordinate(Access::Write, &self.dir, |dir| fs::create_dir_all(dir))
    }

    fn remove_all(&self) -> io::Result<()> {
        missing_is_fine(self.coordinate(Access::Remove, &self.dir, |dir| fs::remove_dir_all(dir)))
    }

    fn child(&self, path: &str) -> Arc<dyn FolderFs> {
        let dir = path.split('/').filter(|p| !p.is_empty()).fold(self.dir.clone(), |p, part| p.join(part));
        Arc::new(LocalFs { dir, coordinator: self.coordinator.clone() })
    }

    fn request_downloads(&self, paths: &[String]) {
        let paths: Vec<PathBuf> = paths.iter().take(64).filter_map(|p| self.at(p).ok()).collect();
        match &self.coordinator {
            Some(c) => c.download(&paths),
            None => request_downloads(&paths),
        }
    }
}

/// Ask iCloud Drive to download files it only has placeholders for.
fn request_downloads(paths: &[PathBuf]) {
    #[cfg(target_os = "macos")]
    for path in paths {
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

// ---------------------------------------------------------------------------
// Folders chosen in the system's folder picker (iPhone, iPad, Android)
// ---------------------------------------------------------------------------

/// The folders the person chose in the system's folder picker, kept by the
/// app on iPhone, iPad and Android, where an app only reaches the folders
/// it was given. Each has a name (`root`) that [`FolderGrant`]s refer to.
pub trait PickedFolders: Send + Sync {
    /// Open the chosen folder `root`.
    fn open(&self, root: &str) -> io::Result<Arc<dyn FolderFs>>;
    /// The chosen folders kept in sync by `service`, with where each is in
    /// the service's own folder when known (`""`: the service's folder
    /// itself), to look for vaults other devices moved there.
    fn roots(&self, service: FolderService) -> Vec<(String, Option<String>)>;
    /// Remember that `root` is kept in sync by `service`, at `path` in the
    /// service's own folder when that turned out.
    fn remember(&self, root: &str, service: FolderService, path: Option<String>);
}

static PICKED: OnceLock<Box<dyn PickedFolders>> = OnceLock::new();

/// Set how this app reaches the folders chosen in the system's folder
/// picker (once, at start).
pub fn set_picked_folders(folders: impl PickedFolders + 'static) {
    let _ = PICKED.set(Box::new(folders));
}

fn picked() -> Option<&'static dyn PickedFolders> {
    PICKED.get().map(|p| &**p)
}

/// Open a vault folder this device reaches through the folder picker.
fn open_grant(grant: &FolderGrant) -> Result<Arc<dyn FolderFs>> {
    let place = || not_found_at(grant.rel.clone());
    let root = picked().ok_or_else(place)?.open(&grant.root).map_err(|_| place())?;
    Ok(if grant.rel.is_empty() { root } else { root.child(&grant.rel) })
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
    /// `.name.icloud` placeholders): where they will be, in the folder.
    pub waiting: Vec<String>,
}

#[derive(Clone)]
enum Parsed {
    Item(ItemFile),
    Meta(MetaFile),
}

/// A file read before: the stamp it had, what it holds.
type Cached = ((i64, u64), Parsed);

/// Files read before, by folder and path: unchanged files are not read
/// again.
static CACHE: Mutex<Option<HashMap<String, Cached>>> = Mutex::new(None);

fn read_text(fs: &dyn FolderFs, rel: &str) -> Option<String> {
    fs.read(rel).ok().flatten().and_then(|b| String::from_utf8(b).ok())
}

fn read_cached(fs: &dyn FolderFs, rel: &str, stamp: (i64, u64), item: bool) -> Option<Parsed> {
    let key = format!("{}\n{rel}", fs.describe());
    // Without a time of change, a file could change without its stamp.
    let cacheable = stamp.0 != 0;
    if cacheable {
        if let Some((s, parsed)) = CACHE.lock().ok()?.as_ref().and_then(|c| c.get(&key)) {
            if *s == stamp {
                return Some(parsed.clone());
            }
        }
    }
    let json = read_text(fs, rel)?;
    let parsed = if item {
        Parsed::Item(serde_json::from_str(&json).ok()?)
    } else {
        Parsed::Meta(serde_json::from_str(&json).ok()?)
    };
    if cacheable {
        if let Ok(mut cache) = CACHE.lock() {
            cache.get_or_insert_with(HashMap::new).insert(key, (stamp, parsed.clone()));
        }
    }
    Some(parsed)
}

/// An iCloud placeholder (`.name.icloud`): the name of the file it stands for.
fn icloud_placeholder(name: &str) -> Option<String> {
    name.strip_prefix('.')?.strip_suffix(".icloud").filter(|n| !n.is_empty()).map(String::from)
}

/// A temporary file left by a write that never finished (older than a day).
fn remove_stale_temp(fs: &dyn FolderFs, rel: &str, entry: &FsEntry) {
    if !entry.name.starts_with(TEMP_PREFIX) || entry.stamp.0 == 0 {
        return;
    }
    let age = millis(Some(SystemTime::now())) - entry.stamp.0;
    if age > 86_400_000 {
        let _ = fs.remove(rel);
    }
}

/// Read everything in a vault's folder on this device (blocking).
pub fn read_folder(dir: &Path) -> Result<FolderRead> {
    read_fs(&LocalFs::new(dir))
}

/// Read everything in a vault's folder (blocking).
pub fn read_fs(fs: &dyn FolderFs) -> Result<FolderRead> {
    let Some(top) = fs.list("").map_err(|e| fs_error(fs, e))? else { return Err(not_found_at(fs.describe())) };
    let has = |name: &str| top.iter().any(|e| !e.dir && e.name == name);
    let mut out = FolderRead::default();
    if has(MOVED_FILE) {
        out.snapshot.moved = read_text(fs, MOVED_FILE).and_then(|j| serde_json::from_str(&j).ok());
        if out.snapshot.moved.is_none() {
            out.snapshot.unreadable += 1;
        }
    }
    match has(VAULT_FILE).then(|| read_text(fs, VAULT_FILE)).flatten() {
        Some(json) => out.vault = Some(VaultFile::parse(&json)?),
        None if has(&format!(".{VAULT_FILE}.icloud")) => {
            out.waiting.push(VAULT_FILE.to_string());
            fs.request_downloads(&out.waiting);
            return Err(not_found_at(format!("{} (still downloading)", fs.describe())));
        }
        None if out.snapshot.moved.is_some() => {}
        None => return Err(not_found_at(fs.describe())),
    }

    for entry in top.iter().filter(|e| !e.dir) {
        if let Some(real) = icloud_placeholder(&entry.name) {
            out.waiting.push(real);
            continue;
        }
        remove_stale_temp(fs, &entry.name, entry);
        if !entry.name.starts_with("meta~") || format::parse_file_name(&entry.name).is_none() {
            continue;
        }
        match read_cached(fs, &entry.name, entry.stamp, false) {
            Some(Parsed::Meta(m)) => out.snapshot.metas.push((entry.name.clone(), m)),
            _ => out.snapshot.unreadable += 1,
        }
    }

    if top.iter().any(|e| e.dir && e.name == ITEMS_DIR) {
        let items = fs.list(ITEMS_DIR).map_err(|e| fs_error(fs, e))?.unwrap_or_default();
        for entry in items.iter().filter(|e| !e.dir) {
            let rel = join_rel(ITEMS_DIR, &entry.name);
            if let Some(real) = icloud_placeholder(&entry.name) {
                out.waiting.push(join_rel(ITEMS_DIR, &real));
                continue;
            }
            remove_stale_temp(fs, &rel, entry);
            if format::parse_file_name(&entry.name).is_none() {
                continue;
            }
            match read_cached(fs, &rel, entry.stamp, true) {
                Some(Parsed::Item(f)) => out.snapshot.items.push((entry.name.clone(), f)),
                _ => out.snapshot.unreadable += 1,
            }
        }
    }
    out.snapshot.items.sort_by(|a, b| a.0.cmp(&b.0));
    out.snapshot.metas.sort_by(|a, b| a.0.cmp(&b.0));
    fs.request_downloads(&out.waiting);
    Ok(out)
}

/// Write and remove the files of a plan in a folder on this device
/// (blocking).
pub fn write_plan(dir: &Path, write: &[(String, String)], remove: &[String]) -> Result<()> {
    write_fs(&LocalFs::new(dir), write, remove)
}

/// Write and remove the files of a plan (blocking).
pub fn write_fs(fs: &dyn FolderFs, write: &[(String, String)], remove: &[String]) -> Result<()> {
    if fs.list("").map_err(|e| fs_error(fs, e))?.is_none() {
        return Err(not_found_at(fs.describe()));
    }
    let checked = |rel: &str| {
        check_rel(rel)
            .and_then(|()| if rel.is_empty() { Err(io::ErrorKind::InvalidInput.into()) } else { Ok(()) })
            .map_err(|_| Error::Core(twosecret_core::Error::invalid(format!("unexpected file name {rel}"))))
    };
    for (rel, contents) in write {
        checked(rel)?;
        fs.write(rel, contents.as_bytes()).map_err(|e| fs_error(fs, e))?;
    }
    for rel in remove {
        checked(rel)?;
        fs.remove(rel).map_err(|e| fs_error(fs, e))?;
    }
    Ok(())
}

/// Remove a vault's items and names from its folder, keeping a `moved.json`
/// that says where it went (blocking). `vault.json` goes too when the vault
/// was deleted.
fn clear_fs(fs: &dyn FolderFs, moved_json: &str, deleted: bool) -> Result<()> {
    fs.write(MOVED_FILE, moved_json.as_bytes()).map_err(|e| fs_error(fs, e))?;
    if let Ok(Some(items)) = fs.list(ITEMS_DIR) {
        for entry in items.iter().filter(|e| !e.dir) {
            if entry.name.ends_with(".json") || entry.name.ends_with(".icloud") {
                let _ = fs.remove(&join_rel(ITEMS_DIR, &entry.name));
            }
        }
        let _ = fs.remove(ITEMS_DIR);
    }
    if let Ok(Some(top)) = fs.list("") {
        for entry in top.iter().filter(|e| !e.dir) {
            if entry.name.starts_with("meta~") || (deleted && entry.name == VAULT_FILE) {
                let _ = fs.remove(&entry.name);
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

/// Where a vault folder that another device keeps at `folder` (its path in
/// the service's own folder) may be in a folder called `root_name`, which is
/// at `root_path` in the service's folder when known: the likeliest first.
fn candidates(root_name: &str, root_path: Option<&str>, folder: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    match root_path {
        Some("") => out.push(folder.to_string()),
        Some(rp) if folder == rp => out.push(String::new()),
        Some(rp) => {
            if let Some(rest) = folder.strip_prefix(&format!("{rp}/")) {
                out.push(rest.to_string());
            }
        }
        None => {}
    }
    let last = folder.rsplit('/').next().unwrap_or_default();
    if !last.is_empty() {
        if root_name == last {
            out.push(String::new());
        }
        if root_name == PARENT_DIR {
            out.push(last.to_string());
        }
        out.push(format!("{PARENT_DIR}/{last}"));
        out.push(last.to_string());
    }
    let mut seen = Vec::new();
    out.retain(|c| {
        let new = !seen.contains(c);
        seen.push(c.clone());
        new
    });
    out
}

/// Whether the folder `rel` in `root` holds vault `vault_id` (any vault for
/// `None`).
fn holds(root: &dyn FolderFs, rel: &str, vault_id: Option<&str>) -> bool {
    let file = join_rel(rel, VAULT_FILE);
    match vault_id {
        None => root.is_file(&file),
        Some(id) => read_text(root, &file).and_then(|j| VaultFile::parse(&j).ok()).is_some_and(|f| f.vault_id == id),
    }
}

/// The folder in `root` that holds the vault another device keeps at
/// `folder` in the service's folder (see [`candidates`]): its path in `root`.
fn locate_in(root: &dyn FolderFs, root_path: Option<&str>, folder: &str, vault_id: Option<&str>) -> Option<String> {
    if folder.is_empty() || folder.split('/').any(|p| p.is_empty() || p == "." || p == "..") {
        return None;
    }
    candidates(&root.name(), root_path, folder).into_iter().find(|rel| holds(root, rel, vault_id))
}

/// Where a vault folder another device moved a vault to is on this device.
fn locate(service: FolderService, folder: &str) -> Option<PathBuf> {
    service_roots().into_iter().filter(|(s, _)| *s == service).find_map(|(_, root)| {
        let rel = locate_in(&LocalFs::new(&root), Some(""), folder, None)?;
        Some(rel.split('/').filter(|p| !p.is_empty()).fold(root, |p, part| p.join(part)))
    })
}

/// Where a chosen folder is in its service's folder, learnt from finding the
/// vault another device keeps at `folder` at `rel` in it.
fn root_path_from(folder: &str, rel: &str) -> Option<String> {
    if rel.is_empty() {
        Some(folder.to_string())
    } else if folder == rel {
        Some(String::new())
    } else {
        folder.strip_suffix(&format!("/{rel}")).map(String::from)
    }
}

/// The vault folder of a vault that another device keeps at `folder` in
/// `service`'s folder, among the folders chosen on this device: the place
/// and how to open it.
fn find_picked(service: FolderService, folder: &str, vault_id: &str) -> Option<(Arc<dyn FolderFs>, VaultLocation)> {
    let picked = picked()?;
    for (root, root_path) in picked.roots(service) {
        let Ok(fs) = picked.open(&root) else { continue };
        let Some(rel) = locate_in(&*fs, root_path.as_deref(), folder, Some(vault_id)) else { continue };
        if root_path.is_none() {
            picked.remember(&root, service, root_path_from(folder, &rel));
        }
        let dir = if rel.is_empty() { fs } else { fs.child(&rel) };
        let location = VaultLocation::Folder { path: dir.describe(), service, grant: Some(FolderGrant { root, rel }) };
        return Some((dir, location));
    }
    None
}

/// The vault folder for a new vault in `parent`: `<parent>/2Secret/<name>-<id>`
/// (without the extra `2Secret` when `parent` is already called that).
pub fn vault_dir(parent: &Path, name: &str, vault_id: &str) -> PathBuf {
    vault_rel(&parent.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), name, vault_id)
        .split('/')
        .fold(parent.to_path_buf(), |p, part| p.join(part))
}

/// Where a new vault's folder goes in a folder called `parent_name`.
fn vault_rel(parent_name: &str, name: &str, vault_id: &str) -> String {
    let dir = format::vault_dir_name(name, vault_id);
    if parent_name == PARENT_DIR {
        dir
    } else {
        format!("{PARENT_DIR}/{dir}")
    }
}

/// Vault folders in `dir`: `dir` itself, or the ones in it (also in a
/// `2Secret` folder in it).
pub fn find_vault_dirs(dir: &Path) -> Vec<PathBuf> {
    find_vault_rels(&LocalFs::new(dir))
        .into_iter()
        .map(|rel| rel.split('/').filter(|p| !p.is_empty()).fold(dir.to_path_buf(), |p, part| p.join(part)))
        .collect()
}

/// Vault folders in a folder (see [`find_vault_dirs`]): their paths in it.
fn find_vault_rels(fs: &dyn FolderFs) -> Vec<String> {
    let Some(top) = fs.list("").ok().flatten() else { return Vec::new() };
    if top.iter().any(|e| !e.dir && (e.name == VAULT_FILE || e.name == MOVED_FILE)) {
        return vec![String::new()];
    }
    let mut out = Vec::new();
    for base in ["", PARENT_DIR] {
        let entries = if base.is_empty() { Some(top.clone()) } else { fs.list(base).ok().flatten() };
        for entry in entries.unwrap_or_default().iter().filter(|e| e.dir && !e.name.starts_with('.')) {
            let rel = join_rel(base, &entry.name);
            if fs.is_file(&join_rel(&rel, VAULT_FILE)) {
                out.push(rel);
            }
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Where a vault's files are
// ---------------------------------------------------------------------------

/// Where a vault's files are: a folder (on this device, or one chosen in the
/// system's folder picker) or a folder on a WebDAV server.
#[derive(Clone)]
pub enum Store {
    Fs(Arc<dyn FolderFs>),
    Dav(Dav),
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Store({})", self.describe())
    }
}

fn dav_not_found(d: &Dav) -> Error {
    not_found_at(d.url().to_string())
}

impl Store {
    /// A folder on this device.
    pub fn local(dir: impl Into<PathBuf>) -> Store {
        Store::Fs(Arc::new(LocalFs::new(dir)))
    }

    /// The files of a vault kept in a folder.
    pub fn of(session: &Session, vault_id: &str) -> Result<Store> {
        let rec = session
            .profile()
            .vault(vault_id)
            .ok_or_else(|| twosecret_core::Error::not_found(format!("vault {vault_id}")))?;
        match &rec.location {
            VaultLocation::Folder { grant: Some(grant), .. } => Ok(Store::Fs(open_grant(grant)?)),
            VaultLocation::Folder { path, .. } => Ok(Store::local(path)),
            VaultLocation::WebDav { url, user, password } => {
                let password = session.open_webdav_password(vault_id, password)?;
                Ok(Store::Dav(Dav::new(url, user, &password)?))
            }
            _ => Err(twosecret_core::Error::invalid("this vault is not kept in a folder").into()),
        }
    }

    /// Where the files are, for people.
    pub fn describe(&self) -> String {
        match self {
            Store::Fs(fs) => fs.describe(),
            Store::Dav(d) => d.url().to_string(),
        }
    }

    /// Read everything in the folder.
    pub async fn read(&self) -> Result<FolderRead> {
        match self {
            Store::Fs(fs) => {
                let fs = fs.clone();
                blocking(move || read_fs(&*fs)).await?
            }
            Store::Dav(d) => read_dav(d).await,
        }
    }

    /// Write and remove files (paths relative to the folder).
    pub async fn write(&self, write: Vec<(String, String)>, remove: Vec<String>) -> Result<()> {
        match self {
            Store::Fs(fs) => {
                let fs = fs.clone();
                blocking(move || write_fs(&*fs, &write, &remove)).await?
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
            Store::Fs(fs) => {
                let fs = fs.clone();
                blocking(move || fs.create().map_err(|e| fs_error(&*fs, e))).await?
            }
            Store::Dav(d) => d.mkcol("").await,
        }
    }

    /// Remove the folder and everything in it (a copy that failed).
    async fn remove_all(&self) {
        match self {
            Store::Fs(fs) => {
                let fs = fs.clone();
                let _ = blocking(move || fs.remove_all()).await;
            }
            Store::Dav(d) => {
                let _ = d.delete("").await;
            }
        }
    }

    /// Clear the folder of a vault that moved away, leaving `moved.json`.
    async fn clear(&self, moved_json: String, deleted: bool) -> Result<()> {
        match self {
            Store::Fs(fs) => {
                let fs = fs.clone();
                blocking(move || {
                    if fs.list("").ok().flatten().is_some() {
                        clear_fs(&*fs, &moved_json, deleted)
                    } else {
                        Ok(())
                    }
                })
                .await?
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
            if let Some((_, location)) = find_moved(*service, folder, vault_id).await? {
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

/// Where this device finds the folder of a vault that another device keeps
/// at `folder` in `service`'s folder: in the storage app's folder on this
/// device, or in a folder chosen in the system's folder picker.
async fn find_moved(service: FolderService, folder: &str, vault_id: &str) -> Result<Option<(Store, VaultLocation)>> {
    let (folder, id) = (folder.to_string(), vault_id.to_string());
    blocking(move || {
        if let Some(dir) = locate(service, &folder) {
            let location = VaultLocation::Folder { path: dir.to_string_lossy().into_owned(), service, grant: None };
            return Some((Store::local(dir), location));
        }
        find_picked(service, &folder, &id).map(|(fs, location)| (Store::Fs(fs), location))
    })
    .await
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
                let Some(found) = find_moved(service, &folder, &id).await? else { continue };
                found
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
    /// A folder chosen in the system's folder picker (iPhone, iPad,
    /// Android), as the app named it: the vault gets a folder in
    /// `<folder>/2Secret`.
    Picked { root: String, service: FolderService },
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
            let store = Store::local(dir.clone());
            store.create().await?;
            let location =
                VaultLocation::Folder { path: dir.to_string_lossy().into_owned(), service: *service, grant: None };
            Ok((store, location, MoveTarget::Folder { service: *service, folder }))
        }
        MoveTo::Picked { root, service } => {
            let picked = picked().ok_or_else(|| not_found_at(root.clone()))?;
            let parent = picked.open(root).map_err(|_| not_found_at(root.clone()))?;
            let rel = vault_rel(&parent.name(), &name, vault_id);
            let dir = parent.child(&rel);
            let make = parent.clone();
            let base = rel.rsplit_once('/').map(|(b, _)| b.to_string());
            blocking(move || {
                if make.list("")?.is_none() {
                    return Err(io::Error::from(io::ErrorKind::NotFound));
                }
                if let Some(base) = base {
                    if make.list(&base)?.is_none() {
                        make.child(&base).create()?;
                    }
                }
                Ok(())
            })
            .await?
            .map_err(|_| not_found_at(parent.describe()))?;
            let store = Store::Fs(dir.clone());
            store.create().await?;
            // The chosen folder is the service's, also for vaults other
            // devices move there later.
            picked.remember(root, *service, None);
            // How the account's other devices find it: its path in the
            // service's folder, as far as this device knows.
            let in_service = picked.roots(*service).into_iter().find(|(r, _)| r == root).and_then(|(_, p)| p);
            let folder = join_rel(in_service.as_deref().unwrap_or_default(), &rel);
            let location = VaultLocation::Folder {
                path: dir.describe(),
                service: *service,
                grant: Some(FolderGrant { root: root.clone(), rel }),
            };
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
    let placeholder = VaultLocation::Folder { path: String::new(), service: FolderService::Other, grant: None };
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
    let location = VaultLocation::Folder { path: dir.to_string_lossy().into_owned(), service, grant: None };
    attach_store(session, Store::local(dir), |_, _| Ok(location)).await
}

/// Add a vault from a folder chosen in the system's folder picker (`root`,
/// as the app named it): the vault's folder, or a folder holding it. With
/// `vault`, the vault (a server placeholder, or a vault whose folder this
/// device lost) and where another device keeps it in the service's folder:
/// that vault is looked for, and the folder is remembered as the service's,
/// so vaults moved there later are found by themselves.
pub async fn attach_picked(
    session: &mut Session,
    root: &str,
    service: FolderService,
    vault: Option<(&str, &str)>,
) -> Result<String> {
    let picked = picked().ok_or_else(|| not_found_at(root.to_string()))?;
    let fs = picked.open(root).map_err(|_| not_found_at(root.to_string()))?;
    let probe = fs.clone();
    let want = vault.map(|(id, folder)| (id.to_string(), folder.to_string()));
    let (rels, learnt) = blocking(move || {
        if let Some((id, folder)) = &want {
            if let Some(rel) = locate_in(&*probe, None, folder, Some(id)) {
                let learnt = root_path_from(folder, &rel);
                return (vec![rel], learnt);
            }
            let rels: Vec<String> =
                find_vault_rels(&*probe).into_iter().filter(|rel| holds(&*probe, rel, Some(id))).collect();
            if !rels.is_empty() {
                return (rels, None);
            }
        }
        (find_vault_rels(&*probe), None)
    })
    .await?;
    let rel = one_vault(rels, &fs.describe(), |r| r.rsplit('/').next().map(String::from))?;
    picked.remember(root, service, learnt);
    let dir = if rel.is_empty() { fs } else { fs.child(&rel) };
    let location = VaultLocation::Folder {
        path: dir.describe(),
        service,
        grant: Some(FolderGrant { root: root.to_string(), rel }),
    };
    attach_store(session, Store::Fs(dir), |_, _| Ok(location)).await
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
        MoveTo::Folder { .. } | MoveTo::Picked { .. } | MoveTo::WebDav { .. } => {
            let (store, location, target) = prepare_target(session, vault_id, &to).await?;
            let same = match (&from, &location) {
                (VaultLocation::Folder { .. }, VaultLocation::Folder { .. }) => {
                    old_store.as_ref().is_some_and(|old| old.describe() == store.describe())
                }
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
