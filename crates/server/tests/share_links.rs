//! Share links: the server gives out the content only for the right proof,
//! and its database keeps a hash of the proof, not the proof itself, so a
//! copy of the database cannot open a link or use up its views.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use twosecret_core::api::{CreateShareRequest, OpenShareRequest, OpenShareResponse, RegisterRequest, SessionResponse};
use twosecret_core::crypto::{encrypt, KdfParams};
use twosecret_core::session::Session;
use twosecret_core::share::{self, SharedField, SharedItem};
use twosecret_core::util::{b64, now};

fn json<T: serde::Serialize>(method: &str, path: &str, token: Option<&str>, body: &T) -> Request<Body> {
    let mut req = Request::builder().method(method).uri(path).header("content-type", "application/json");
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    req.body(Body::from(serde_json::to_vec(body).unwrap())).unwrap()
}

#[tokio::test]
async fn the_database_holds_no_usable_proof() {
    let (session, _sk, keys) = Session::create_account_with_keys(
        "Alice",
        "alice@example.com",
        "correct horse battery staple",
        KdfParams::insecure_for_tests(),
        "Personal",
    )
    .unwrap();
    let account = session.account().clone();
    let state = twosecret_server::AppState::in_memory(Default::default()).unwrap();
    let app = twosecret_server::app(state.clone());

    let register = RegisterRequest {
        account_id: account.id.clone(),
        email: account.email.clone(),
        name: account.name.clone(),
        salt: account.salt.clone(),
        kdf: account.kdf.clone(),
        auth_key: b64(keys.auth_key.as_bytes()),
        keyset: account.keyset.clone(),
        invite_code: None,
        device_name: None,
    };
    let resp = app.clone().oneshot(json("POST", "/api/v1/register", None, &register)).await.unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let token = serde_json::from_slice::<SessionResponse>(&body).unwrap().token;

    let item = SharedItem {
        title: "Wi-Fi".into(),
        fields: vec![SharedField { label: "password".into(), value: "hunter2".into(), concealed: true }],
        notes: String::new(),
        urls: vec![],
    };
    let sealed = share::seal(&item, None).unwrap();
    let create = CreateShareRequest {
        id: sealed.id.clone(),
        data: sealed.data.clone(),
        proof: sealed.proof.clone(),
        label: encrypt(session.account_key(), b"Wi-Fi", b"2secret/v1/share-label"),
        expires_at: now() + 3600,
        max_views: Some(2),
        password: false,
    };
    let resp = app.clone().oneshot(json("POST", "/api/v1/shares", Some(&token), &create)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The database has the proof's hash, never the proof.
    let id = sealed.id.clone();
    let stored: String = state
        .db
        .run(move |c| Ok(c.query_row("SELECT proof FROM shares WHERE id = ?1", [&id], |r| r.get(0))?))
        .await
        .unwrap();
    assert!(stored.starts_with("h1."), "{stored}");
    assert!(!stored.contains(sealed.proof.as_str()));

    // The stored value does not open the link; the proof does.
    let open = |proof: &str| {
        json("POST", &format!("/api/v1/shares/{}/open", sealed.id), None, &OpenShareRequest { proof: proof.into() })
    };
    let resp = app.clone().oneshot(open(&stored["h1.".len()..])).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = app.clone().oneshot(open(&sealed.proof)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let answer: OpenShareResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(answer.views_left, Some(1));
    assert_eq!(share::open(&sealed.id, &answer.data, &sealed.key, None).unwrap(), item);

    // A link made before proofs were hashed (the proof itself is stored).
    let legacy = share::seal(&item, None).unwrap();
    let (legacy_id, legacy_data, legacy_proof, owner) =
        (legacy.id.clone(), legacy.data.clone(), legacy.proof.clone(), account.id.clone());
    state
        .db
        .run(move |c| {
            c.execute(
                "INSERT INTO shares (id, owner_id, label, data, proof, password, created_at, expires_at, views_left, wrong)
                 VALUES (?1, ?2, '', ?3, ?4, 0, ?5, ?6, NULL, 0)",
                rusqlite::params![legacy_id, owner, legacy_data, legacy_proof, now(), now() + 3600],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let open_legacy = json(
        "POST",
        &format!("/api/v1/shares/{}/open", legacy.id),
        None,
        &OpenShareRequest { proof: legacy.proof.clone() },
    );
    let resp = app.oneshot(open_legacy).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
