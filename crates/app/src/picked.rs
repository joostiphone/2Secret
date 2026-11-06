//! The folders chosen in the system's folder picker on iPhone, iPad and
//! Android, where an app only reaches the folders it was given. They are
//! kept in `picked-folders.json` in the app's data folder (with what the
//! system needs to open them again: a bookmark on iOS, a document tree on
//! Android) and offered to the folder sync
//! ([`twosecret_client::folder::PickedFolders`]). Vault locations name them
//! by a short id.

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use twosecret_client::folder::{FolderFs, PickedFolders};
use twosecret_core::profile::{FolderGrant, FolderService};

#[cfg(target_os = "android")]
use crate::android_folders as native;
#[cfg(target_os = "ios")]
use crate::ios_folders as native;

/// A folder the system's folder picker gave.
pub struct Chosen {
    /// What the system needs to open it again.
    pub token: String,
    /// The same folder chosen twice has the same key.
    pub key: String,
    /// Its name, for people.
    pub name: String,
    /// The service that keeps it in sync, when the system says.
    pub service: Option<FolderService>,
    /// Where it is in that service's folder, when known.
    pub service_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Root {
    id: String,
    token: String,
    key: String,
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service: Option<FolderService>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<String>,
}

static ROOTS: Mutex<Option<Vec<Root>>> = Mutex::new(None);

fn file() -> PathBuf {
    crate::platform::data_dir().join("picked-folders.json")
}

fn with_roots<T>(f: impl FnOnce(&mut Vec<Root>, &mut bool) -> T) -> T {
    let mut guard = ROOTS.lock().unwrap_or_else(|p| p.into_inner());
    let roots = guard.get_or_insert_with(|| {
        std::fs::read_to_string(file()).ok().and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default()
    });
    let mut changed = false;
    let out = f(roots, &mut changed);
    if changed {
        let path = file();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(json) = serde_json::to_string_pretty(&*roots) {
            let tmp = path.with_extension("json.tmp");
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
    }
    out
}

/// What the folder sync asks about chosen folders.
struct Registry;

impl PickedFolders for Registry {
    fn open(&self, root: &str) -> io::Result<Arc<dyn FolderFs>> {
        let token = with_roots(|roots, _| roots.iter().find(|r| r.id == root).map(|r| r.token.clone()))
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        let (fs, renewed) = native::open(&token)?;
        if let Some(token) = renewed {
            with_roots(|roots, changed| {
                if let Some(r) = roots.iter_mut().find(|r| r.id == root) {
                    r.token = token;
                    *changed = true;
                }
            });
        }
        Ok(fs)
    }

    fn roots(&self, service: FolderService) -> Vec<(String, Option<String>)> {
        with_roots(|roots, _| {
            roots.iter().filter(|r| r.service == Some(service)).map(|r| (r.id.clone(), r.path.clone())).collect()
        })
    }

    fn remember(&self, root: &str, service: FolderService, path: Option<String>) {
        with_roots(|roots, changed| {
            if let Some(r) = roots.iter_mut().find(|r| r.id == root) {
                if r.service != Some(service) {
                    r.service = Some(service);
                    *changed = true;
                }
                if path.is_some() && r.path != path {
                    r.path = path;
                    *changed = true;
                }
            }
        });
    }
}

/// Offer the chosen folders to the folder sync (once, at start).
pub fn install() {
    twosecret_client::folder::set_picked_folders(Registry);
}

/// Let the person choose a folder, for `service`. Returns its id.
pub async fn choose(service: Option<FolderService>) -> Option<String> {
    let chosen = native::pick().await?;
    let id = with_roots(|roots, changed| {
        *changed = true;
        if let Some(r) = roots.iter_mut().find(|r| r.key == chosen.key) {
            r.token = chosen.token.clone();
            if chosen.service.is_some() {
                r.service = chosen.service;
                r.path = chosen.service_path.clone();
            }
            return r.id.clone();
        }
        let id: String = twosecret_core::util::new_id().chars().take(12).collect();
        roots.push(Root {
            id: id.clone(),
            token: chosen.token.clone(),
            key: chosen.key.clone(),
            name: chosen.name.clone(),
            service: chosen.service.or(service),
            path: chosen.service_path.clone(),
        });
        id
    });
    Some(id)
}

/// The name of a chosen folder.
pub fn name(root: &str) -> Option<String> {
    with_roots(|roots, _| roots.iter().find(|r| r.id == root).map(|r| r.name.clone()))
}

/// The service a chosen folder turned out to be in (iCloud Drive), if the
/// system said.
pub fn service(root: &str) -> Option<FolderService> {
    with_roots(|roots, _| roots.iter().find(|r| r.id == root).and_then(|r| r.service))
}

/// Where a vault's folder is, for people: the chosen folder's name and the
/// way down from it.
pub fn display(grant: &FolderGrant) -> String {
    let base = name(&grant.root).unwrap_or_default();
    match (base.is_empty(), grant.rel.is_empty()) {
        (_, true) => base,
        (true, _) => grant.rel.clone(),
        _ => format!("{base}/{}", grant.rel),
    }
}
