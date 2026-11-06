//! Vaults in storage folders, end to end: real files in a temporary folder,
//! a real server on localhost, two "devices" of one account.

use std::path::{Path, PathBuf};

use twosecret_client::folder::{self, MoveTo};
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

fn files_in(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for entry in walk(dir) {
        out.push(entry.strip_prefix(dir).unwrap().to_string_lossy().into_owned());
    }
    out.sort();
    out
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if e.path().is_dir() {
                out.extend(walk(&e.path()));
            } else {
                out.push(e.path());
            }
        }
    }
    out
}

async fn sync_folders(s: &mut Session) {
    for outcome in folder::sync_folders(s).await.unwrap() {
        outcome.result.unwrap();
    }
}

#[tokio::test]
async fn a_folder_vault_shared_by_two_devices() {
    let (mut a, _) =
        Session::create_account("Alice", "alice@example.com", PW, KdfParams::insecure_for_tests(), "Personal").unwrap();
    let mut b = Session::open_with_account_key(a.profile().clone(), a.account_key().clone()).unwrap();
    let cloud = temp_dir("cloud");

    let work = folder::create_folder_vault(&mut a, "Work", "", &cloud, FolderService::Other).await.unwrap();
    let dir = PathBuf::from(a.profile().vault(&work).unwrap().location.folder().unwrap());
    assert!(dir.starts_with(cloud.join("2Secret")));
    assert!(dir.join("vault.json").is_file());
    let id = a.add_item(&work, Item::login("Mail", "alice", "pw-1", None)).unwrap();
    sync_folders(&mut a).await;
    assert!(!a.profile().has_pending_folder_changes());

    // The other device adds the folder (picking the folder above it works).
    let added = folder::attach_folder(&mut b, &cloud, None).await.unwrap();
    assert_eq!(added, work);
    assert_eq!(b.vault(&work).unwrap().name, "Work");
    assert_eq!(b.item(&id).unwrap().password(), Some("pw-1"));

    // Changes go both ways; each device writes only its own files.
    let mut item = b.item(&id).unwrap().clone();
    item.set_value("password", "pw-2");
    b.update_item(item).unwrap();
    sync_folders(&mut b).await;
    sync_folders(&mut a).await;
    assert_eq!(a.item(&id).unwrap().password(), Some("pw-2"));
    let names = files_in(&dir);
    let (ta, tb) = (a.device_tag(), b.device_tag());
    assert!(names.iter().any(|n| n.ends_with(&format!("~{ta}.json"))));
    assert!(names.iter().any(|n| n.ends_with(&format!("~{tb}.json"))));
    assert!(!names.iter().any(|n| n.contains(".~tmp-")));

    // Nothing in the folder is readable without the vault key.
    for path in walk(&dir) {
        let text = std::fs::read_to_string(path).unwrap();
        assert!(!text.contains("pw-1") && !text.contains("pw-2") && !text.contains("Mail") && !text.contains("Work\""));
    }

    // A deletion reaches the other device.
    a.delete_item(&id).unwrap();
    sync_folders(&mut a).await;
    sync_folders(&mut b).await;
    assert!(b.item(&id).is_none());

    // A missing folder is reported, and the vault stays.
    let moved_away = cloud.join("elsewhere");
    std::fs::rename(&dir, &moved_away).unwrap();
    let outcomes = folder::sync_folders(&mut b).await.unwrap();
    assert!(outcomes.iter().any(|o| o.vault_id == work && o.not_found()));
    assert!(b.vault(&work).is_some());
    std::fs::rename(&moved_away, &dir).unwrap();

    // Deleting the vault removes it on the other device too.
    let keep = b.add_item(&work, Item::login("Keep", "x", "y", None)).unwrap();
    sync_folders(&mut b).await;
    sync_folders(&mut a).await;
    assert!(a.item(&keep).is_some());
    folder::delete_folder_vault(&mut a, &work).await.unwrap();
    assert!(a.vault(&work).is_none());
    sync_folders(&mut b).await;
    assert!(b.vault(&work).is_none());
    assert_eq!(files_in(&dir), vec!["moved.json".to_string()]);
    let _ = std::fs::remove_dir_all(&cloud);
}

/// The only test that changes `HOME` (where the storage apps' folders are
/// looked for), so it cannot race with another.
#[tokio::test]
async fn a_vault_moves_between_the_server_a_folder_and_one_device() {
    let home = temp_dir("home");
    let dropbox = home.join("Dropbox");
    std::fs::create_dir_all(&dropbox).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("USERPROFILE", &home);
    assert!(folder::service_roots().iter().any(|(s, p)| *s == FolderService::Dropbox && p == &dropbox));

    let url = start_server().await;
    let kdf = KdfParams::insecure_for_tests();
    let (mut laptop, sk) =
        client::signup(&url, "Alice", "alice@example.com", PW, None, "laptop", "Personal", kdf).await.unwrap();
    let work = laptop.create_vault("Work", "").unwrap();
    let one = laptop.add_item(&work, Item::login("One", "alice", "pw-1", None)).unwrap();
    client::sync(&mut laptop).await.unwrap();
    let mut desktop = client::signin(&url, "alice@example.com", PW, &sk, "desktop").await.unwrap();
    assert!(desktop.item(&one).is_some());

    // Server -> Dropbox.
    folder::move_vault(&mut laptop, &work, MoveTo::Folder { parent: dropbox.clone(), service: FolderService::Dropbox })
        .await
        .unwrap();
    let info = laptop.vault(&work).unwrap();
    assert!(matches!(info.location, VaultLocation::Folder { service: FolderService::Dropbox, .. }));
    assert!(laptop.item(&one).is_some());
    assert!(laptop.profile().vault(&work).unwrap().leftovers.is_empty(), "the placeholder is empty");

    // The desktop finds it in its own Dropbox folder.
    client::sync(&mut desktop).await.unwrap();
    sync_folders(&mut desktop).await;
    let on_desktop = desktop.vault(&work).unwrap();
    assert!(on_desktop.location.is_folder(), "{:?}", on_desktop.location);
    assert!(desktop.item(&one).is_some());

    // A device without the folder sees where the vault went.
    let mut phone = client::signin(&url, "alice@example.com", PW, &sk, "phone").await.unwrap();
    let placeholder = phone.vault(&work).unwrap();
    assert!(placeholder.is_placeholder());
    assert_eq!(placeholder.item_count, 0);
    assert!(phone.add_item(&work, Item::login("No", "x", "y", None)).is_err());

    // Changes go through the folder.
    let two = desktop.add_item(&work, Item::login("Two", "alice", "pw-2", None)).unwrap();
    sync_folders(&mut desktop).await;
    sync_folders(&mut laptop).await;
    assert!(laptop.item(&two).is_some());

    // Dropbox -> server: everything is on the server again, for everyone.
    folder::move_vault(&mut laptop, &work, MoveTo::Account).await.unwrap();
    assert!(laptop.vault(&work).unwrap().location.is_account());
    assert!(!laptop.profile().has_pending_changes());
    sync_folders(&mut desktop).await; // reads moved.json: back to the server
    client::sync(&mut desktop).await.unwrap();
    assert!(desktop.vault(&work).unwrap().location.is_account());
    assert!(desktop.item(&one).is_some() && desktop.item(&two).is_some());
    client::sync(&mut phone).await.unwrap();
    assert!(!phone.vault(&work).unwrap().is_placeholder());
    assert!(phone.item(&one).is_some() && phone.item(&two).is_some());
    assert_eq!(phone.vault(&work).unwrap().item_count, 2);

    // Server -> this device only: gone from the server and the other devices.
    folder::move_vault(&mut laptop, &work, MoveTo::Device).await.unwrap();
    assert!(laptop.vault(&work).unwrap().location.is_device());
    assert!(laptop.item(&one).is_some());
    client::sync(&mut laptop).await.unwrap();
    assert!(laptop.vault(&work).is_some(), "the server does not take a vault kept here");
    client::sync(&mut phone).await.unwrap();
    assert!(phone.vault(&work).is_none());

    // A shared vault cannot leave the server.
    let team = laptop.create_vault("Team", "").unwrap();
    client::sync(&mut laptop).await.unwrap();
    let (_bob, _) =
        client::signup(&url, "Bob", "bob@example.com", PW, None, "bob", "Personal", KdfParams::insecure_for_tests())
            .await
            .unwrap();
    client::share_vault(&mut laptop, &team, "bob@example.com", twosecret_core::profile::Role::Viewer).await.unwrap();
    let err = folder::move_vault(&mut laptop, &team, MoveTo::Device).await.unwrap_err();
    assert!(err.to_string().contains("shared"), "{err}");
    let _ = std::fs::remove_dir_all(&home);
}
