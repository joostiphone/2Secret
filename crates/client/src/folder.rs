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

use twosecret_core::api::UpdateVaultRequest;
use twosecret_core::folder::{
    self as format, FolderPlan, FolderReport, ItemFile, MetaFile, Snapshot, VaultFile, ITEMS_DIR, MOVED_FILE,
    PARENT_DIR, TEMP_PREFIX, VAULT_FILE,
};
use twosecret_core::profile::{FolderService, MoveTarget, MovedTo, VaultLocation};
use twosecret_core::session::Session;
use twosecret_core::util::now;

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
    let dir = match access
        .with_session(|s| s.profile().vault(vault_id).and_then(|v| v.location.folder().map(PathBuf::from)))
    {
        Ok(Some(dir)) => dir,
        Ok(None) => return (Err(twosecret_core::Error::not_found(format!("vault {vault_id}")).into()), 0),
        Err(e) => return (Err(e), 0),
    };
    let read_dir = dir.clone();
    let read = match blocking(move || read_folder(&read_dir)).await {
        Ok(Ok(read)) => read,
        Ok(Err(e)) | Err(e) => return (Err(e), 0),
    };
    let waiting = read.waiting.len();
    (sync_read(access, vault_id, dir, read).await, waiting)
}

async fn sync_read<A: SessionAccess>(
    access: &mut A,
    vault_id: &str,
    dir: PathBuf,
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
        return Ok(plan.report);
    }
    let (write, remove) = (plan.write.clone(), plan.remove.clone());
    let write_dir = dir.clone();
    blocking(move || write_plan(&write_dir, &write, &remove)).await??;
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
    }
    Ok(())
}

/// Sync every vault kept in a storage folder, each on its own: a folder that
/// is missing does not stop the others. Server placeholders of vaults that
/// moved to a folder this device has are taken from there first.
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

/// Sync every vault in a storage folder (see [`sync_folders_with`]).
pub async fn sync_folders(session: &mut Session) -> Result<Vec<FolderOutcome>> {
    let mut access = session;
    sync_folders_with(&mut access).await
}

/// Take vaults that another device moved from the server to a storage
/// folder from that folder, when this device has it. Returns their ids.
pub async fn attach_moved_with<A: SessionAccess>(access: &mut A) -> Result<Vec<String>> {
    let moved: Vec<(String, FolderService, String)> = access.with_session(|s| {
        s.vaults()
            .into_iter()
            .filter(|v| v.is_placeholder())
            .filter_map(|v| match v.moved?.to {
                MoveTarget::Folder { service, folder } => Some((v.id, service, folder)),
                _ => None,
            })
            .collect()
    })?;
    let mut attached = Vec::new();
    for (id, service, folder) in moved {
        let Some(dir) = blocking(move || locate(service, &folder)).await? else { continue };
        let read_dir = dir.clone();
        let Ok(Ok(read)) = blocking(move || read_folder(&read_dir)).await else { continue };
        let (Some(file), None) = (&read.vault, &read.snapshot.moved) else { continue };
        if file.vault_id != id {
            continue;
        }
        let location = VaultLocation::Folder { path: dir.to_string_lossy().into_owned(), service };
        let ok = access.with_session(|s| s.attach_folder(file, &read.snapshot, location).is_ok())?;
        if ok {
            let _ = sync_read(access, &id, dir, read).await;
            attached.push(id);
        }
    }
    Ok(attached)
}

// ---------------------------------------------------------------------------
// Creating, adding, moving and deleting folder vaults
// ---------------------------------------------------------------------------

/// Create a vault in a storage folder: in `<parent>/2Secret/<name>-<id>`.
pub async fn create_folder_vault(
    session: &mut Session,
    name: &str,
    description: &str,
    parent: &Path,
    service: FolderService,
) -> Result<String> {
    if !parent.is_dir() {
        return Err(not_found(parent));
    }
    let id = session.create_vault_at(name, description, VaultLocation::Folder { path: String::new(), service })?;
    let dir = vault_dir(parent, name, &id);
    let result: Result<()> = async {
        session.set_vault_folder(&id, VaultLocation::Folder { path: dir.to_string_lossy().into_owned(), service })?;
        let files = session.folder_export(&id)?;
        let write_dir = dir.clone();
        blocking(move || {
            fs::create_dir_all(&write_dir).map_err(|e| io_error(&write_dir, e))?;
            write_plan(&write_dir, &files, &[])
        })
        .await??;
        sync_folder(session, &id).await.map(|_| ())
    }
    .await;
    if let Err(e) = result {
        let _ = session.delete_vault(&id);
        return Err(e);
    }
    Ok(id)
}

/// Add a vault that is in a storage folder (made on another device), or
/// take a vault this device knows as a server placeholder from its folder.
/// `dir` is the vault's folder or a folder holding one vault folder.
pub async fn attach_folder(session: &mut Session, dir: &Path, service: Option<FolderService>) -> Result<String> {
    let found_in = dir.to_path_buf();
    let dirs = blocking(move || find_vault_dirs(&found_in)).await?;
    let dir = match dirs.as_slice() {
        [one] => one.clone(),
        [] => {
            return Err(twosecret_core::Error::invalid(format!("there is no 2Secret vault in {}", dir.display())).into())
        }
        _ => {
            let names: Vec<String> =
                dirs.iter().filter_map(|d| d.file_name().map(|n| n.to_string_lossy().into_owned())).collect();
            return Err(twosecret_core::Error::invalid(format!(
                "there are several vaults in this folder; choose one of: {}",
                names.join(", ")
            ))
            .into());
        }
    };
    let read_dir = dir.clone();
    let read = blocking(move || read_folder(&read_dir)).await??;
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
    let file = read.vault.clone().ok_or_else(|| not_found(&dir))?;
    let service = match service {
        Some(s) => s,
        None => {
            let probe = dir.clone();
            blocking(move || service_of(&probe)).await?.unwrap_or_default()
        }
    };
    let location = VaultLocation::Folder { path: dir.to_string_lossy().into_owned(), service };
    let id = session.attach_folder(&file, &read.snapshot, location)?;
    let mut access = &mut *session;
    sync_read(&mut access, &id, dir, read).await?;
    Ok(id)
}

/// Where to move a vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MoveTo {
    /// To the account's server (or, for an account without one, with the
    /// account on this device).
    Account,
    /// Only this device.
    Device,
    /// A storage folder: the vault gets a folder in `<parent>/2Secret`.
    Folder { parent: PathBuf, service: FolderService },
}

/// Move a vault between the server, this device and storage folders. Its
/// contents are copied and checked before anything is removed, and the
/// vault keeps its id and key, so other devices of the account follow it.
pub async fn move_vault(session: &mut Session, vault_id: &str, to: MoveTo) -> Result<()> {
    session.can_move(vault_id)?;
    let rec = session
        .profile()
        .vault(vault_id)
        .cloned()
        .ok_or_else(|| twosecret_core::Error::not_found(format!("vault {vault_id}")))?;
    let linked = session.server().is_some();
    let from = rec.location.clone();

    // Up to date first, wherever it is now.
    match &from {
        VaultLocation::Account if linked => {
            sync(session).await?;
        }
        VaultLocation::Folder { .. } => match sync_folder(session, vault_id).await {
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
            linked
                && session
                    .profile()
                    .vault(vault_id)
                    .is_some_and(|v| v.sync_state == twosecret_core::profile::SyncState::Synced)
        }
        VaultLocation::Folder { .. } => linked && rec.on_server,
        VaultLocation::Device => false,
    };

    let (location, target) = match &to {
        MoveTo::Account => (VaultLocation::Account, MoveTarget::Account),
        MoveTo::Device => (VaultLocation::Device, MoveTarget::Device),
        MoveTo::Folder { parent, service } => {
            let name = session.vault(vault_id).map(|v| v.name).unwrap_or_default();
            let dir = vault_dir(parent, &name, vault_id);
            if from.folder().is_some_and(|f| Path::new(f) == dir) {
                return Ok(());
            }
            let files = session.folder_export(vault_id)?;
            let expected = files.iter().filter(|(p, _)| p.starts_with(ITEMS_DIR)).count();
            let (write_dir, parent) = (dir.clone(), parent.clone());
            let read = blocking(move || -> Result<FolderRead> {
                if !parent.is_dir() {
                    return Err(not_found(&parent));
                }
                fs::create_dir_all(&write_dir).map_err(|e| io_error(&write_dir, e))?;
                if let Ok(existing) = fs::read_to_string(write_dir.join(VAULT_FILE)) {
                    // Another vault there: never overwrite it.
                    let existing = VaultFile::parse(&existing)?;
                    let ours: VaultFile = VaultFile::parse(&files[0].1)?;
                    if existing.vault_id != ours.vault_id {
                        return Err(twosecret_core::Error::invalid("that folder holds another vault").into());
                    }
                }
                let _ = fs::remove_file(write_dir.join(MOVED_FILE));
                write_plan(&write_dir, &files, &[])?;
                read_folder(&write_dir)
            })
            .await??;
            // Check that everything arrived and opens.
            let file = read.vault.as_ref().ok_or_else(|| not_found(&dir))?;
            session.check_vault_file(vault_id, file)?;
            let readable = read.snapshot.items.iter().filter(|(_, f)| f.data.is_some()).count();
            if readable < expected || read.snapshot.unreadable > 0 {
                return Err(twosecret_core::Error::Storage("the copy in the folder is incomplete".into()).into());
            }
            let folder = relative_to_service(*service, &dir);
            (
                VaultLocation::Folder { path: dir.to_string_lossy().into_owned(), service: *service },
                MoveTarget::Folder { service: *service, folder },
            )
        }
    };
    let moved = MovedTo { to: target.clone(), at: now() };

    // The server: mark its copy as a placeholder before leaving it, so the
    // other devices stop adding to it.
    if on_server && matches!(target, MoveTarget::Folder { .. }) {
        let client = client_for(session)?;
        let meta = session.placeholder_meta(vault_id, Some(moved.clone()))?;
        let key_rev = session.profile().vault(vault_id).map(|v| v.key_rev);
        if let Err(e) = client.update_vault(vault_id, &UpdateVaultRequest { meta, key_rev }).await {
            if let VaultLocation::Folder { path, .. } = &location {
                if from.folder() != Some(path.as_str()) && from.is_account() {
                    let dir = PathBuf::from(path);
                    let _ = blocking(move || fs::remove_dir_all(dir)).await;
                }
            }
            return Err(e);
        }
    }

    session.relocate_vault(vault_id, location)?;

    // Leave the old place.
    if let VaultLocation::Folder { path, .. } = &from {
        let moved_json = session.moved_file(vault_id, &moved)?;
        let dir = PathBuf::from(path);
        let _ = blocking(move || clear_folder(&dir, &moved_json, false)).await;
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

/// Delete a vault kept in a storage folder: its files go (a `moved.json`
/// tells the other devices), and so does its server placeholder.
pub async fn delete_folder_vault(session: &mut Session, vault_id: &str) -> Result<()> {
    let rec = session
        .profile()
        .vault(vault_id)
        .cloned()
        .ok_or_else(|| twosecret_core::Error::not_found(format!("vault {vault_id}")))?;
    if let VaultLocation::Folder { path, .. } = &rec.location {
        let moved_json = session.moved_file(vault_id, &MovedTo { to: MoveTarget::Deleted, at: now() })?;
        let dir = PathBuf::from(path);
        let _ = blocking(move || if dir.is_dir() { clear_folder(&dir, &moved_json, true) } else { Ok(()) }).await;
    }
    session.delete_vault(vault_id)?;
    if session.server().is_some() && rec.on_server {
        sync(session).await?;
    }
    Ok(())
}
