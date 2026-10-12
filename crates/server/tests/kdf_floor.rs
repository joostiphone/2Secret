//! The server refuses accounts whose key derivation is weaker than the minimum.
//! This file is its own test process, so no other test has lifted the minimum.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use twosecret_core::api::RegisterRequest;
use twosecret_core::crypto::KdfParams;
use twosecret_core::session::Session;
use twosecret_core::util::b64;

#[tokio::test]
async fn weak_kdf_parameters_are_refused() {
    let (session, _sk, keys) = Session::create_account_with_keys(
        "Alice",
        "alice@example.com",
        "correct horse battery staple",
        KdfParams::default(),
        "Personal",
    )
    .unwrap();
    let account = session.account().clone();
    let register = |kdf: KdfParams| RegisterRequest {
        account_id: account.id.clone(),
        email: account.email.clone(),
        name: account.name.clone(),
        salt: account.salt.clone(),
        kdf,
        auth_key: b64(keys.auth_key.as_bytes()),
        keyset: account.keyset.clone(),
        invite_code: None,
        device_name: None,
    };
    let app = twosecret_server::app(twosecret_server::AppState::in_memory(Default::default()).unwrap());
    let post = |body: &RegisterRequest| {
        Request::post("/api/v1/register")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    };

    let weak = KdfParams { memory_kib: 1024, iterations: 1, ..KdfParams::default() };
    let resp = app.clone().oneshot(post(&register(weak))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = app.oneshot(post(&register(KdfParams::default()))).await.unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
}
