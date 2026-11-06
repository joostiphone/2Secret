//! Vaults in folders chosen in the system's folder picker (iPhone, iPad,
//! Android), end to end: a "phone" reaches a folder only through what the
//! picker gave it (here a stand-in that behaves like Android's document
//! trees: no atomic replace, no times of change), next to a laptop that
//! reaches the same folder on its file system.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use twosecret_client::folder::{self, FolderFs, FsEntry, MoveTo, PickedFolders};
use twosecret_client::{self as client};
use twosecret_core::crypto::KdfParams;
use twosecret_core::item::Item;
use twosecret_core::profile::{FolderService, VaultLocation};
use twosecret_core::session::Session;
use twosecret_server::{AppState, Config};

const PW: &str = "correct horse battery staple";

async fn start_server() -> String {
    let state = AppState::in_memory(Config::default()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = twosecret_server::serve(listener, state).await;
    });
    format!("http://{addr}")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("2secret-{name}-{}", twosecret_core::util::new_id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A folder the way Android's document trees offer it: files are written in
/// place (no rename over an existing file), there are no times of change,
/// and making a folder needs its parent.
struct Tree {
    dir: PathBuf,
}

impl Tree {
    fn at(&self, rel: &str) -> PathBuf {
        rel.split('/').filter(|p| !p.is_empty()).fold(self.dir.clone(), |p, part| p.join(part))
    }
}

impl FolderFs for Tree {
    fn describe(&self) -> String {
        format!("tree:{}", self.dir.display())
    }
    fn name(&self) -> String {
        self.dir.file_name().unwrap().to_string_lossy().into_owned()
    }
    fn list(&self, dir: &str) -> io::Result<Option<Vec<FsEntry>>> {
        let path = self.at(dir);
        if !path.is_dir() {
            return Ok(None);
        }
        let mut out = Vec::new();
        for e in std::fs::read_dir(path)?.flatten() {
            let meta = e.metadata()?;
            out.push(FsEntry {
                name: e.file_name().to_string_lossy().into_owned(),
                dir: meta.is_dir(),
                stamp: (0, meta.len()),
            });
        }
        Ok(Some(out))
    }
    fn read(&self, path: &str) -> io::Result<Option<Vec<u8>>> {
        match std::fs::read(self.at(path)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn write(&self, path: &str, contents: &[u8]) -> io::Result<()> {
        let path = self.at(path);
        let parent = path.parent().unwrap();
        if !parent.is_dir() {
            // Documents are made one folder at a time.
            if !parent.parent().is_some_and(|p| p.is_dir()) {
                return Err(io::ErrorKind::NotFound.into());
            }
            std::fs::create_dir(parent)?;
        }
        std::fs::write(path, contents)
    }
    fn remove(&self, path: &str) -> io::Result<()> {
        let path = self.at(path);
        let result = if path.is_dir() { std::fs::remove_dir(&path) } else { std::fs::remove_file(&path) };
        match result {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
    fn create(&self) -> io::Result<()> {
        match std::fs::create_dir(&self.dir) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            other => other,
        }
    }
    fn remove_all(&self) -> io::Result<()> {
        std::fs::remove_dir_all(&self.dir)
    }
    fn child(&self, path: &str) -> Arc<dyn FolderFs> {
        Arc::new(Tree { dir: self.at(path) })
    }
}

/// A folder "chosen" on the phone: the folder, its service, where it is in
/// the service's folder.
type Root = (PathBuf, Option<FolderService>, Option<String>);

/// The folders chosen on the phone, by name.
#[derive(Clone, Default)]
struct Chosen(Arc<Mutex<HashMap<String, Root>>>);

impl Chosen {
    fn choose(&self, name: &str, dir: &Path) {
        self.0.lock().unwrap().insert(name.into(), (dir.to_path_buf(), None, None));
    }
}

impl PickedFolders for Chosen {
    fn open(&self, root: &str) -> io::Result<Arc<dyn FolderFs>> {
        let dir = self.0.lock().unwrap().get(root).map(|r| r.0.clone()).ok_or(io::ErrorKind::NotFound)?;
        Ok(Arc::new(Tree { dir }))
    }
    fn roots(&self, service: FolderService) -> Vec<(String, Option<String>)> {
        let map = self.0.lock().unwrap();
        let mut out: Vec<_> =
            map.iter().filter(|(_, r)| r.1 == Some(service)).map(|(k, r)| (k.clone(), r.2.clone())).collect();
        out.sort();
        out
    }
    fn remember(&self, root: &str, service: FolderService, path: Option<String>) {
        if let Some(r) = self.0.lock().unwrap().get_mut(root) {
            r.1 = Some(service);
            if path.is_some() {
                r.2 = path;
            }
        }
    }
}

async fn sync_folders(s: &mut Session) {
    for outcome in folder::sync_folders(s).await.unwrap() {
        outcome.result.unwrap();
    }
}

fn grant_of(s: &Session, vault: &str) -> Option<(String, String)> {
    match &s.profile().vault(vault)?.location {
        VaultLocation::Folder { grant: Some(g), .. } => Some((g.root.clone(), g.rel.clone())),
        _ => None,
    }
}

/// One test for everything: the chosen folders are set once per process.
#[tokio::test]
async fn a_phone_reaches_vault_folders_through_the_folder_picker() {
    let chosen = Chosen::default();
    folder::set_picked_folders(chosen.clone());

    // --- A folder vault without a server: laptop and phone side by side ---
    let (mut laptop, _) =
        Session::create_account("Alice", "alice@example.com", PW, KdfParams::insecure_for_tests(), "Personal").unwrap();
    let mut phone = Session::open_with_account_key(laptop.profile().clone(), laptop.account_key().clone()).unwrap();
    let cloud = temp_dir("synced");
    let work = folder::create_folder_vault(&mut laptop, "Work", "", &cloud, FolderService::Other).await.unwrap();
    let mail = laptop.add_item(&work, Item::login("Mail", "alice", "pw-1", None)).unwrap();
    sync_folders(&mut laptop).await;

    // The phone is given the synced folder and finds the vault in it.
    chosen.choose("synced", &cloud);
    let added = folder::attach_picked(&mut phone, "synced", FolderService::Other, None).await.unwrap();
    assert_eq!(added, work);
    let (root, rel) = grant_of(&phone, &work).unwrap();
    assert_eq!(root, "synced");
    assert!(rel.starts_with("2Secret/Work-"), "{rel}");
    assert_eq!(phone.item(&mail).unwrap().password(), Some("pw-1"));

    // Changes go both ways, also without atomic writes or times of change.
    for round in 2..5 {
        let mut item = phone.item(&mail).unwrap().clone();
        item.set_value("password", &format!("pw-{round}"));
        phone.update_item(item).unwrap();
        sync_folders(&mut phone).await;
        sync_folders(&mut laptop).await;
        assert_eq!(laptop.item(&mail).unwrap().password(), Some(format!("pw-{round}").as_str()));
    }
    let bank = laptop.add_item(&work, Item::login("Bank", "alice", "pw-b", None)).unwrap();
    sync_folders(&mut laptop).await;
    sync_folders(&mut phone).await;
    assert!(phone.item(&bank).is_some());

    // A vault made on the phone, in the chosen folder.
    let notes = folder::create_vault_in(
        &mut phone,
        "Notes",
        "",
        &MoveTo::Picked { root: "synced".into(), service: FolderService::Other },
    )
    .await
    .unwrap();
    let pin = phone.add_item(&notes, Item::login("Pin", "alice", "1234", None)).unwrap();
    sync_folders(&mut phone).await;
    let (_, notes_rel) = grant_of(&phone, &notes).unwrap();
    let notes_dir = cloud.join(&notes_rel);
    assert!(notes_dir.join("vault.json").is_file());
    let added = folder::attach_folder(&mut laptop, &notes_dir, None).await.unwrap();
    assert_eq!(added, notes);
    assert!(laptop.item(&pin).is_some());

    // A folder the phone can no longer open: reported, and the vault stays.
    chosen.0.lock().unwrap().remove("synced");
    let outcomes = folder::sync_folders(&mut phone).await.unwrap();
    assert!(outcomes.iter().any(|o| o.vault_id == work && o.not_found()), "{outcomes:?}");
    assert!(phone.item(&mail).is_some());
    chosen.choose("synced", &cloud);
    sync_folders(&mut phone).await;

    // Moving a vault from the chosen folder to this phone only.
    folder::move_vault(&mut phone, &notes, MoveTo::Device).await.unwrap();
    assert!(phone.vault(&notes).unwrap().location.is_device());
    assert!(phone.item(&pin).is_some());
    assert!(notes_dir.join("moved.json").is_file());
    let _ = std::fs::remove_dir_all(&cloud);

    // --- Following vaults that a laptop moved to "iCloud Drive" ---
    let url = start_server().await;
    let kdf = KdfParams::insecure_for_tests();
    let (mut laptop, sk) =
        client::signup(&url, "Bob", "bob@example.com", PW, None, "laptop", "Personal", kdf).await.unwrap();
    let docs = temp_dir("icloud").join("Documents");
    std::fs::create_dir_all(&docs).unwrap();
    let private = laptop.create_vault("Private", "").unwrap();
    let family = laptop.create_vault("Family", "").unwrap();
    let one = laptop.add_item(&private, Item::login("One", "bob", "pw-1", None)).unwrap();
    let two = laptop.add_item(&family, Item::login("Two", "bob", "pw-2", None)).unwrap();
    client::sync(&mut laptop).await.unwrap();
    let mut phone = client::signin(&url, "bob@example.com", PW, &sk, "phone").await.unwrap();

    let to_icloud = MoveTo::Folder { parent: docs.clone(), service: FolderService::ICloudDrive };
    folder::move_vault(&mut laptop, &private, to_icloud.clone()).await.unwrap();
    client::sync(&mut phone).await.unwrap();
    sync_folders(&mut phone).await;
    let placeholder = phone.vault(&private).unwrap();
    assert!(placeholder.is_placeholder(), "the phone has no iCloud folder yet");
    let Some(twosecret_core::profile::MoveTarget::Folder { folder: where_, .. }) = placeholder.moved.map(|m| m.to)
    else {
        panic!("the placeholder says where the vault went");
    };

    // The person chooses the folder once…
    chosen.choose("docs", &docs);
    let added =
        folder::attach_picked(&mut phone, "docs", FolderService::ICloudDrive, Some((&private, &where_))).await.unwrap();
    assert_eq!(added, private);
    assert!(phone.item(&one).is_some());
    assert!(!phone.vault(&private).unwrap().is_placeholder());

    // …and a vault moved there later is found by itself.
    folder::move_vault(&mut laptop, &family, to_icloud).await.unwrap();
    client::sync(&mut phone).await.unwrap();
    sync_folders(&mut phone).await;
    assert!(!phone.vault(&family).unwrap().is_placeholder(), "followed into the chosen folder");
    assert_eq!(grant_of(&phone, &family).map(|g| g.0), Some("docs".to_string()));
    assert!(phone.item(&two).is_some());

    // Changes made on the phone reach the laptop through the folder.
    let three = phone.add_item(&family, Item::login("Three", "bob", "pw-3", None)).unwrap();
    sync_folders(&mut phone).await;
    sync_folders(&mut laptop).await;
    assert!(laptop.item(&three).is_some());

    // Choosing a folder with no vault in it says so.
    let empty = temp_dir("empty");
    chosen.choose("empty", &empty);
    let err = folder::attach_picked(&mut phone, "empty", FolderService::Other, None).await.unwrap_err();
    assert!(err.to_string().contains("no 2Secret vault"), "{err}");
    let _ = std::fs::remove_dir_all(docs.parent().unwrap());
    let _ = std::fs::remove_dir_all(&empty);
}
