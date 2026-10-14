//! End-to-end tests: real HTTP server on localhost, real client, real crypto.

use twosecret_client::{self as client, Client};
use twosecret_core::crypto::{KdfParams, WrappedKey};
use twosecret_core::item::{Category, Item};
use twosecret_core::profile::Role;
use twosecret_core::session::Session;
use twosecret_server::{AppState, Config, SignupMode};

async fn start_server(config: Config) -> String {
    let state = AppState::in_memory(config).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum_serve(listener, state).await;
    });
    format!("http://{addr}")
}

async fn axum_serve(listener: tokio::net::TcpListener, state: AppState) {
    let _ = twosecret_server::serve(listener, state).await;
}

fn kdf() -> KdfParams {
    KdfParams::insecure_for_tests()
}

const PW: &str = "correct horse battery staple";

#[tokio::test]
async fn signup_signin_sync_between_devices() {
    let url = start_server(Config::default()).await;
    let health = Client::new(&url).health().await.unwrap();
    assert_eq!(health.status, "ok");

    let (mut laptop, sk) =
        client::signup(&url, "Alice", "alice@example.com", PW, None, "laptop", "Personal", kdf()).await.unwrap();
    let vault = laptop.default_vault_id().unwrap();
    let id = laptop.add_item(&vault, Item::login("GitHub", "alice", "pw-1", Some("https://github.com"))).unwrap();
    let report = client::sync(&mut laptop).await.unwrap();
    assert_eq!(report.uploaded, 1);

    // Second device signs in with e-mail + password + Secret Key.
    let mut phone = client::signin(&url, "Alice@Example.com", PW, &sk, "phone").await.unwrap();
    assert_eq!(phone.vaults().len(), 1);
    assert_eq!(phone.vaults()[0].name, "Personal");
    assert_eq!(phone.item(&id).unwrap().password(), Some("pw-1"));

    // Edit on the phone, see it on the laptop.
    let mut item = phone.item(&id).unwrap().clone();
    item.set_value("password", "pw-2");
    phone.update_item(item).unwrap();
    client::sync(&mut phone).await.unwrap();
    let r = client::sync(&mut laptop).await.unwrap();
    assert_eq!(r.downloaded, 1);
    assert_eq!(laptop.item(&id).unwrap().password(), Some("pw-2"));
    assert_eq!(laptop.item(&id).unwrap().password_history[0].value, "pw-1");

    // New vault created on the laptop appears on the phone.
    let work = laptop.create_vault("Work", "").unwrap();
    laptop.add_item(&work, Item::new(Category::SecureNote, "Wifi")).unwrap();
    client::sync(&mut laptop).await.unwrap();
    let r = client::sync(&mut phone).await.unwrap();
    assert_eq!(r.vaults_added, 1);
    assert_eq!(phone.find_vault("Work").unwrap().item_count, 1);

    // Renames and deletes propagate.
    laptop.update_vault(&work, "Werk", "", None).unwrap();
    client::sync(&mut laptop).await.unwrap();
    client::sync(&mut phone).await.unwrap();
    assert!(phone.find_vault("Werk").is_ok());
    laptop.delete_vault(&work).unwrap();
    client::sync(&mut laptop).await.unwrap();
    let r = client::sync(&mut phone).await.unwrap();
    assert_eq!(r.vaults_removed, 1);
    assert_eq!(phone.vaults().len(), 1);

    // The server never saw plaintext: wrong password / Secret Key fails.
    let err = client::signin(&url, "alice@example.com", "wrong password", &sk, "x").await.unwrap_err();
    assert_eq!(err.status(), Some(401));
    let other_sk = twosecret_core::crypto::SecretKey::generate();
    assert!(client::signin(&url, "alice@example.com", PW, &other_sk, "x").await.is_err());
    // Unknown users get plausible prelogin data (no account enumeration).
    let pre = Client::new(&url).prelogin("nobody@example.com").await.unwrap();
    let pre2 = Client::new(&url).prelogin("nobody@example.com").await.unwrap();
    assert_eq!(pre.salt, pre2.salt);
}

#[tokio::test]
async fn profile_photo_follows_the_account() {
    let url = start_server(Config::default()).await;
    let (mut laptop, sk) =
        client::signup(&url, "Alice", "alice@example.com", PW, None, "laptop", "Personal", kdf()).await.unwrap();
    let photo = "data:image/jpeg;base64,/9j/4AAQSkZJRg==";
    laptop.set_avatar(Some(photo)).unwrap();
    client::sync(&mut laptop).await.unwrap();
    assert_eq!(laptop.avatar_to_upload(), None, "sent");
    // The server keeps only ciphertext.
    let stored = laptop.profile().account.avatar.clone().unwrap();
    assert!(!stored.as_str().contains("/9j/"));

    // A new device has it right after signing in.
    let mut phone = client::signin(&url, "alice@example.com", PW, &sk, "phone").await.unwrap();
    assert_eq!(phone.avatar().as_deref(), Some(photo));

    // Removed on the phone, gone on the laptop.
    phone.set_avatar(None).unwrap();
    client::sync(&mut phone).await.unwrap();
    laptop.recheck_avatar();
    let report = client::sync(&mut laptop).await.unwrap();
    assert!(report.avatar_changed);
    assert_eq!(laptop.avatar(), None);
    // Not asked again within the hour.
    assert!(!laptop.avatar_check_due());
}

#[tokio::test]
async fn concurrent_edits_resolve() {
    let url = start_server(Config::default()).await;
    let (mut a, sk) = client::signup(&url, "Bob", "bob@example.com", PW, None, "a", "Personal", kdf()).await.unwrap();
    let v = a.default_vault_id().unwrap();
    let id = a.add_item(&v, Item::login("Bank", "bob", "start", None)).unwrap();
    client::sync(&mut a).await.unwrap();
    let mut b = client::signin(&url, "bob@example.com", PW, &sk, "b").await.unwrap();

    let mut ia = a.item(&id).unwrap().clone();
    ia.set_value("password", "from-a");
    a.update_item(ia).unwrap();
    let mut ib = b.item(&id).unwrap().clone();
    ib.notes = "from-b".into();
    ib.set_value("password", "from-b");
    b.update_item(ib).unwrap();

    client::sync(&mut a).await.unwrap();
    let r = client::sync(&mut b).await.unwrap();
    assert!(r.conflicts >= 1);
    client::sync(&mut a).await.unwrap();
    // Both devices converge on the same version and no password is lost.
    let fa = a.item(&id).unwrap();
    let fb = b.item(&id).unwrap();
    assert_eq!(fa.password(), fb.password());
    let all: Vec<&str> =
        std::iter::once(fa.password().unwrap()).chain(fa.password_history.iter().map(|h| h.value.as_str())).collect();
    assert!(all.contains(&"from-a") && all.contains(&"from-b"), "{all:?}");
    assert!(!a.profile().has_pending_changes());
    assert!(!b.profile().has_pending_changes());
}

#[tokio::test]
async fn vault_sharing_and_permissions() {
    let url = start_server(Config::default()).await;
    let (mut alice, _) =
        client::signup(&url, "Alice", "alice@example.com", PW, None, "a", "Personal", kdf()).await.unwrap();
    let (mut bob, _) = client::signup(&url, "Bob", "bob@example.com", PW, None, "b", "Personal", kdf()).await.unwrap();
    let family = alice.create_vault("Family", "").unwrap();
    let netflix = alice.add_item(&family, Item::login("Netflix", "family", "popcorn", None)).unwrap();
    let bob_info = client::share_vault(&mut alice, &family, "bob@example.com", Role::Viewer).await.unwrap();
    assert_eq!(bob_info.name, "Bob");
    // Bob published an ML-KEM key, so the vault key was sealed post-quantum.
    assert!(bob_info.pq_public_key.is_some());
    let bob_api = client::client_for(&bob).unwrap();
    let wrapped_for_bob = || async {
        let vaults = bob_api.vaults().await.unwrap();
        vaults.into_iter().find(|v| v.id == family).unwrap().wrapped_key
    };
    assert!(matches!(wrapped_for_bob().await, WrappedKey::HybridSealed { .. }));

    let r = client::sync(&mut bob).await.unwrap();
    assert_eq!(r.vaults_added, 1);
    // After Bob's sync the server keeps only a wrapping with Bob's own account key.
    assert!(matches!(wrapped_for_bob().await, WrappedKey::Symmetric { .. }));
    client::sync(&mut bob).await.unwrap();
    assert!(bob.vault_keys_to_rewrap().is_empty());
    let shared = bob.find_vault("Family").unwrap();
    assert_eq!(shared.role, Role::Viewer);
    assert!(!shared.is_owner);
    assert_eq!(bob.item(&netflix).unwrap().password(), Some("popcorn"));

    // Viewers cannot write (locally refused, and the server would refuse too).
    let mut edit = bob.item(&netflix).unwrap().clone();
    edit.notes = "hack".into();
    assert!(bob.update_item(edit).is_err());

    // Promote Bob to editor; his edits reach Alice.
    client::set_member_role(&mut alice, &family, &bob.account().id, Role::Editor).await.unwrap();
    client::sync(&mut bob).await.unwrap();
    let mut edit = bob.item(&netflix).unwrap().clone();
    edit.notes = "shared note".into();
    bob.update_item(edit).unwrap();
    client::sync(&mut bob).await.unwrap();
    client::sync(&mut alice).await.unwrap();
    assert_eq!(alice.item(&netflix).unwrap().notes, "shared note");

    let members = client::vault_members(&alice, &family).await.unwrap();
    assert_eq!(members.len(), 2);
    assert_eq!(alice.vault(&family).unwrap().member_count, 2);

    // Revoke access: the vault disappears from Bob's devices.
    client::remove_member(&mut alice, &family, &bob.account().id).await.unwrap();
    let r = client::sync(&mut bob).await.unwrap();
    assert_eq!(r.vaults_removed, 1);
    assert!(bob.item(&netflix).is_none());

    // Unknown recipients are reported.
    assert!(client::share_vault(&mut alice, &family, "nobody@example.com", Role::Viewer).await.is_err());
}

#[tokio::test]
async fn removing_a_member_replaces_the_vault_key() {
    use twosecret_core::api::{ItemChange, SyncRequest, VaultSyncRequest};
    use twosecret_core::crypto::decrypt_json;
    use twosecret_core::profile::aad;

    let url = start_server(Config::default()).await;
    let signup = |name: &'static str, email: &'static str| {
        let url = url.clone();
        async move { client::signup(&url, name, email, PW, None, name, "Personal", kdf()).await.unwrap().0 }
    };
    let mut alice = signup("Alice", "alice@example.com").await;
    let mut bob = signup("Bob", "bob@example.com").await;
    let mut carol = signup("Carol", "carol@example.com").await;
    let team = alice.create_vault("Team", "").unwrap();
    let wifi = alice.add_item(&team, Item::login("Wi-Fi", "office", "old-secret", None)).unwrap();
    client::share_vault(&mut alice, &team, "bob@example.com", Role::Editor).await.unwrap();
    client::share_vault(&mut alice, &team, "carol@example.com", Role::Viewer).await.unwrap();
    client::sync(&mut bob).await.unwrap();
    client::sync(&mut carol).await.unwrap();
    let old_key = alice.vault_key(&team).unwrap().clone();
    assert_eq!(carol.vault_key(&team), Some(&old_key));

    // Bob edits offline while Alice removes Carol.
    let mut edit = bob.item(&wifi).unwrap().clone();
    edit.set_value("password", "new-secret");
    bob.update_item(edit).unwrap();
    client::remove_member(&mut alice, &team, &carol.account().id).await.unwrap();
    let new_key = alice.vault_key(&team).unwrap().clone();
    assert_ne!(new_key, old_key);
    assert_eq!(alice.item(&wifi).unwrap().password(), Some("old-secret"));
    assert_eq!(alice.profile().vault(&team).unwrap().key_rev, 1);

    // Carol is out; Bob gets the new key and his edit is not lost.
    client::sync(&mut carol).await.unwrap();
    assert!(carol.vault(&team).is_none());
    client::sync(&mut bob).await.unwrap();
    assert_eq!(bob.vault_key(&team), Some(&new_key));
    assert!(!bob.profile().has_pending_changes());
    client::sync(&mut alice).await.unwrap();
    assert_eq!(alice.item(&wifi).unwrap().password(), Some("new-secret"));

    // Everything on the server is encrypted with the new key; the old key
    // Carol may have kept opens nothing.
    let api = client::client_for(&alice).unwrap();
    let req = SyncRequest {
        vaults: vec![VaultSyncRequest { vault_id: team.clone(), since: 0, changes: vec![], key_rev: None }],
    };
    let resp = api.sync(&req).await.unwrap();
    let vault = resp.vaults.iter().find(|v| v.id == team).unwrap();
    assert!(decrypt_json::<serde_json::Value>(&old_key, &vault.meta, &aad::vault_meta(&team)).is_err());
    let items = &resp.results.iter().find(|r| r.vault_id == team).unwrap().changes;
    assert!(!items.is_empty());
    for item in items {
        let data = item.data.as_ref().unwrap();
        assert!(decrypt_json::<serde_json::Value>(&old_key, data, &aad::item(&team, &item.id)).is_err());
        assert!(decrypt_json::<serde_json::Value>(&new_key, data, &aad::item(&team, &item.id)).is_ok());
    }

    // Writes encrypted with the old key are refused.
    let forged = alice.profile().item(&wifi).unwrap().data.clone();
    let stale = SyncRequest {
        vaults: vec![VaultSyncRequest {
            vault_id: team.clone(),
            since: 0,
            changes: vec![ItemChange {
                id: "11111111-2222-4333-8444-555555555555".into(),
                base_revision: 0,
                data: forged,
            }],
            key_rev: Some(0),
        }],
    };
    let resp = api.sync(&stale).await.unwrap();
    let result = resp.results.iter().find(|r| r.vault_id == team).unwrap();
    assert_eq!(result.stale_key.len(), 1);
    assert!(result.accepted.is_empty());

    // The key can also be replaced on request, e.g. after someone left.
    client::rotate_vault_key(&mut alice, &team).await.unwrap();
    client::sync(&mut bob).await.unwrap();
    assert_eq!(bob.vault_key(&team), alice.vault_key(&team));
    assert_eq!(bob.item(&wifi).unwrap().password(), Some("new-secret"));
    assert!(bob.undecryptable().is_empty());
}

#[tokio::test]
async fn local_account_connects_later_and_password_change() {
    let url = start_server(Config::default()).await;
    let (mut s, sk) = Session::create_account("Carol", "carol@example.com", PW, kdf(), "Personal").unwrap();
    let v = s.default_vault_id().unwrap();
    s.add_item(&v, Item::login("Local", "c", "p", None)).unwrap();
    let r = client::connect(&mut s, &url, PW, &sk, None, "desktop").await.unwrap();
    assert_eq!(r.uploaded, 1);
    assert!(!s.profile().has_pending_changes());

    client::change_password(&mut s, PW, "an even better password", &sk).await.unwrap();
    // The old password no longer works anywhere.
    assert!(client::signin(&url, "carol@example.com", PW, &sk, "x").await.is_err());
    let other = client::signin(&url, "carol@example.com", "an even better password", &sk, "x").await.unwrap();
    assert_eq!(other.item_count(), 1);
    // Our own session survived the change; other sessions were revoked.
    client::sync(&mut s).await.unwrap();
    let devices = client::client_for(&s).unwrap().devices().await.unwrap();
    assert!(devices.iter().any(|d| d.current));

    client::sign_out(&mut s).await.unwrap();
    assert!(matches!(client::sync(&mut s).await, Err(client::Error::Unauthorized)));
    client::reauthenticate(&mut s, "an even better password", &sk, "desktop").await.unwrap();
    client::sync(&mut s).await.unwrap();

    client::delete_server_account(&mut s, "an even better password", &sk).await.unwrap();
    assert!(s.server().is_none());
    assert_eq!(s.item_count(), 1, "local data is kept");
    assert!(client::signin(&url, "carol@example.com", "an even better password", &sk, "x").await.is_err());
}

#[tokio::test]
async fn signup_modes() {
    let url = start_server(Config {
        signups: SignupMode::Invite,
        invite_codes: vec!["family-2026".into()],
        ..Config::default()
    })
    .await;
    let err = client::signup(&url, "D", "d@example.com", PW, None, "x", "P", kdf()).await.unwrap_err();
    assert_eq!(err.status(), Some(403));
    client::signup(&url, "D", "d@example.com", PW, Some("family-2026"), "x", "P", kdf()).await.unwrap();
    let dup = client::signup(&url, "D", "d@example.com", PW, Some("family-2026"), "x", "P", kdf()).await.unwrap_err();
    assert_eq!(dup.status(), Some(409));

    let closed = start_server(Config { signups: SignupMode::Closed, ..Config::default() }).await;
    assert!(!Client::new(&closed).health().await.unwrap().signups_open);
    let err = client::signup(&closed, "E", "e@example.com", PW, None, "x", "P", kdf()).await.unwrap_err();
    assert_eq!(err.status(), Some(403));
}

#[tokio::test]
async fn limits_for_a_public_server() {
    // Sign-ups per address (the test client is 127.0.0.1) and in total.
    let url = start_server(Config { signups_per_ip: Some(2), ..Config::default() }).await;
    client::signup(&url, "A", "a@example.com", PW, None, "x", "P", kdf()).await.unwrap();
    client::signup(&url, "B", "b@example.com", PW, None, "x", "P", kdf()).await.unwrap();
    let err = client::signup(&url, "C", "c@example.com", PW, None, "x", "P", kdf()).await.unwrap_err();
    assert_eq!(err.status(), Some(429));
    let full = start_server(Config { max_accounts: Some(1), ..Config::default() }).await;
    client::signup(&full, "A", "a@example.com", PW, None, "x", "P", kdf()).await.unwrap();
    let err = client::signup(&full, "B", "b@example.com", PW, None, "x", "P", kdf()).await.unwrap_err();
    assert_eq!(err.status(), Some(403));

    // Storage per account: what does not fit stays on the device.
    let url = start_server(Config { account_quota_bytes: Some(40_000), ..Config::default() }).await;
    let (mut s, sk) = client::signup(&url, "Q", "q@example.com", PW, None, "x", "P", kdf()).await.unwrap();
    let vault = s.default_vault_id().unwrap();
    let big = |title: &str| {
        let mut item = Item::new(Category::SecureNote, title);
        item.notes = "x".repeat(15_000);
        item
    };
    let first = s.add_item(&vault, big("First")).unwrap();
    assert_eq!(client::sync(&mut s).await.unwrap().uploaded, 1);
    let second = s.add_item(&vault, big("Second")).unwrap();
    let report = client::sync(&mut s).await.unwrap();
    assert_eq!((report.uploaded, report.over_quota), (0, 1));
    assert!(s.item(&second).is_some(), "the item stays on the device");
    let api = Client::new(&url).with_token(s.server_token().unwrap());
    let account = api.account().await.unwrap();
    assert_eq!(account.storage_quota, Some(40_000));
    assert!(account.storage_used.unwrap() > 15_000 && account.storage_used.unwrap() <= 40_000);

    // Making room lets it through on the next sync.
    s.delete_item(&first).unwrap();
    client::sync(&mut s).await.unwrap();
    let report = client::sync(&mut s).await.unwrap();
    assert_eq!(report.over_quota, 0);
    let phone = client::signin(&url, "q@example.com", PW, &sk, "y").await.unwrap();
    assert!(phone.item(&second).is_some() && phone.item(&first).is_none());
    assert!(api.account().await.unwrap().storage_used.unwrap() <= 40_000);
}

#[tokio::test]
async fn login_rate_limiting() {
    let url = start_server(Config::default()).await;
    let (_s, sk) = client::signup(&url, "F", "f@example.com", PW, None, "x", "P", kdf()).await.unwrap();
    for _ in 0..10 {
        let e = client::signin(&url, "f@example.com", "wrong password", &sk, "x").await.unwrap_err();
        assert_eq!(e.status(), Some(401));
    }
    let e = client::signin(&url, "f@example.com", PW, &sk, "x").await.unwrap_err();
    assert_eq!(e.status(), Some(429));
}

#[tokio::test]
async fn server_enforces_read_only_access() {
    use twosecret_core::api::{ItemChange, SyncRequest, VaultSyncRequest};
    let url = start_server(Config::default()).await;
    let (mut alice, _) = client::signup(&url, "A", "a@example.com", PW, None, "a", "Personal", kdf()).await.unwrap();
    let (mut bob, _) = client::signup(&url, "B", "b@example.com", PW, None, "b", "Personal", kdf()).await.unwrap();
    let shared = alice.create_vault("Shared", "").unwrap();
    let id = alice.add_item(&shared, Item::login("X", "x", "secret", None)).unwrap();
    client::share_vault(&mut alice, &shared, "b@example.com", Role::Viewer).await.unwrap();
    client::sync(&mut bob).await.unwrap();

    // Bob bypasses his client's checks and talks to the API directly.
    let api = client::client_for(&bob).unwrap();
    let forged = bob.profile().item(&id).unwrap().data.clone();
    let resp = api
        .sync(&SyncRequest {
            vaults: vec![VaultSyncRequest {
                vault_id: shared.clone(),
                since: 0,
                changes: vec![
                    ItemChange { id: id.clone(), base_revision: 1, data: None },
                    ItemChange { id: "new-item".into(), base_revision: 0, data: forged },
                ],
                key_rev: None,
            }],
        })
        .await
        .unwrap();
    let result = resp.results.iter().find(|r| r.vault_id == shared).unwrap();
    assert_eq!(result.rejected.len(), 2);
    assert!(result.accepted.is_empty());

    // Bob cannot rename, delete or share the vault either.
    assert_eq!(
        api.update_vault(
            &shared,
            &twosecret_core::api::UpdateVaultRequest {
                meta: bob.profile().vault(&shared).unwrap().meta.clone(),
                key_rev: None
            }
        )
        .await
        .unwrap_err()
        .status(),
        Some(403)
    );
    assert!(api.members(&shared).await.is_ok());
    // Deleting as a non-owner only removes Bob's own access.
    api.delete_vault(&shared).await.unwrap();
    client::sync(&mut alice).await.unwrap();
    assert_eq!(alice.item(&id).unwrap().password(), Some("secret"));
    assert_eq!(alice.vault(&shared).unwrap().member_count, 1);

    // An outsider sees nothing.
    let (carol, _) = client::signup(&url, "C", "c@example.com", PW, None, "c", "Personal", kdf()).await.unwrap();
    let carol_api = client::client_for(&carol).unwrap();
    assert_eq!(carol_api.members(&shared).await.unwrap_err().status(), Some(404));
    let resp = carol_api
        .sync(&SyncRequest {
            vaults: vec![VaultSyncRequest { vault_id: shared.clone(), since: 0, changes: vec![], key_rev: None }],
        })
        .await
        .unwrap();
    assert!(resp.results.iter().all(|r| r.vault_id != shared));
}

#[tokio::test]
async fn password_changed_on_other_device() {
    let url = start_server(Config::default()).await;
    let (mut a, sk) = client::signup(&url, "G", "g@example.com", PW, None, "a", "Personal", kdf()).await.unwrap();
    let v = a.default_vault_id().unwrap();
    let id = a.add_item(&v, Item::login("Mail", "g", "pw", None)).unwrap();
    client::sync(&mut a).await.unwrap();
    let b = client::signin(&url, "g@example.com", PW, &sk, "b").await.unwrap();
    let b_profile = b.profile().clone();
    drop(b);

    client::change_password(&mut a, PW, "the new master password", &sk).await.unwrap();

    // Device B still has the old keyset: the new password fails locally...
    assert!(Session::unlock(b_profile.clone(), "the new master password", &sk).is_err());
    // ...but works online, which also updates B's keyset.
    let mut b = client::unlock_online(b_profile.clone(), "the new master password", &sk, "b").await.unwrap();
    assert_eq!(b.item(&id).unwrap().password(), Some("pw"));
    client::sync(&mut b).await.unwrap();
    assert!(Session::unlock(b.profile().clone(), "the new master password", &sk).is_ok());
    // The old password is useless online.
    assert!(client::unlock_online(b_profile, PW, &sk, "b").await.is_err());
}
