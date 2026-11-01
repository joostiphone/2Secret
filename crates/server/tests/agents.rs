//! Agents elsewhere: the relay. An agent pairs with a code, the owner
//! confirms it, requests and answers pass through as sealed envelopes the
//! server cannot read, and the server enforces signatures, nonces, limits,
//! expiry and revocation.

use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;
use twosecret_core::agent::AgentError;
use twosecret_core::agent_remote::{
    self, AgentRecordData, HttpSignature, PairingCode, RemoteKeys, HTTP_HEADER, PAIRING_SECONDS, REQUEST_SECONDS,
};
use twosecret_core::api::{
    AgentAnswerRequest, AgentDto, AgentRequestDto, AgentRequestState, AgentRequestStatus, ConfirmAgentRequest,
    CreatePairingRequest, PairAgentRequest, PairAgentResponse, PairingInfo, PostAgentRequest, RegisterRequest,
    SessionResponse,
};
use twosecret_core::crypto::{AccountPublicKeys, KdfParams};
use twosecret_core::session::Session;
use twosecret_core::util::{b64, now};
use twosecret_server::{app, AppState, Config};

type App = axum::Router;

fn as_owner<T: serde::Serialize>(method: &str, path: &str, token: &str, body: Option<&T>) -> Request<Body> {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"));
    match body {
        Some(b) => req.body(Body::from(serde_json::to_vec(b).unwrap())).unwrap(),
        None => req.body(Body::empty()).unwrap(),
    }
}

/// A call signed by the agent, at time `at`.
fn agent_at(keys: &RemoteKeys, method: &str, path: &str, body: Vec<u8>, at: i64) -> Request<Body> {
    let sig = HttpSignature::sign(keys, method, path, &body, at);
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header(HTTP_HEADER, sig.header())
        .body(Body::from(body))
        .unwrap()
}

fn agent<T: serde::Serialize>(keys: &RemoteKeys, method: &str, path: &str, body: Option<&T>) -> Request<Body> {
    let body = body.map(|b| serde_json::to_vec(b).unwrap()).unwrap_or_default();
    agent_at(keys, method, path, body, now())
}

async fn read<T: serde::de::DeserializeOwned>(resp: axum::response::Response) -> T {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&body)))
}

async fn error_code(resp: axum::response::Response) -> String {
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"].as_str().unwrap().to_string()
}

struct Owner {
    session: Session,
    token: String,
    keys: AccountPublicKeys,
}

async fn sign_up(app: &App, email: &str) -> Owner {
    let (session, _sk, keys) = Session::create_account_with_keys(
        "Alice",
        email,
        "correct horse battery staple",
        KdfParams::insecure_for_tests(),
        "Personal",
    )
    .unwrap();
    let account = session.account().clone();
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
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&register).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(resp.status().is_success(), "register: {}", resp.status());
    let token = read::<SessionResponse>(resp).await.token;
    let keys = session.public_keys();
    Owner { session, token, keys }
}

fn setup() -> (AppState, App) {
    let state = AppState::in_memory(Config { max_open_agent_requests: 2, ..Config::default() }).unwrap();
    (state.clone(), app(state))
}

/// The owner makes a code and registers it; the agent looks the account up
/// and pairs. Returns the code and the agent's keys.
async fn pair(app: &App, owner: &Owner, name: &str) -> (PairingCode, RemoteKeys) {
    let code = PairingCode::new("https://sync.example", &owner.keys).unwrap();
    let resp = app
        .clone()
        .oneshot(as_owner(
            "POST",
            "/api/v1/agents/pairings",
            &owner.token,
            Some(&CreatePairingRequest { token_hash: code.token_hash() }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let keys = RemoteKeys::generate();
    let path = format!("/api/v1/agent/pairing/{}", code.token());
    let resp =
        app.clone().oneshot(Request::builder().method("GET").uri(&path).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let info: PairingInfo = read(resp).await;
    let account = AccountPublicKeys::from_b64(&info.x25519, Some(&info.ml_kem)).unwrap();
    assert!(code.matches(&account), "the server's keys are the code's keys");

    let proof = agent_remote::seal_proof(&code, &account, &keys, name, "1.0", Some("build-1")).unwrap();
    let req = PairAgentRequest { token: code.token(), keys: keys.public(), proof };
    let resp = app.clone().oneshot(agent(&keys, "POST", "/api/v1/agent/pair", Some(&req))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let answer: PairAgentResponse = read(resp).await;
    assert_eq!(answer.agent_id, keys.agent_id());
    (code, keys)
}

/// The owner opens the proof and confirms the agent.
async fn confirm(app: &App, owner: &Owner, code: &PairingCode, keys: &RemoteKeys) -> AgentRecordData {
    let resp = app.clone().oneshot(as_owner("GET", "/api/v1/agents", &owner.token, None::<&()>)).await.unwrap();
    let agents: Vec<AgentDto> = read(resp).await;
    let dto = agents.iter().find(|a| a.id == keys.agent_id()).expect("pending agent listed");
    assert!(dto.record.is_none());
    let proof = agent_remote::open_proof(
        owner.session.keyset(),
        dto.token_hash.as_deref().unwrap(),
        dto.proof.as_ref().unwrap(),
    )
    .unwrap();
    proof.check(code, &dto.keys).unwrap();
    let record = AgentRecordData {
        name: proof.name.clone(),
        version: proof.version.clone(),
        keys: dto.keys.clone(),
        fingerprint: dto.keys.fingerprint().unwrap(),
        paired_at: now(),
        device: proof.device.clone(),
        paired_on: Some("MacBook".into()),
    };
    let account_id = owner.session.account().id.clone();
    let enc = record.seal(owner.session.account_key(), &account_id, &keys.agent_id()).unwrap();
    let resp = app
        .clone()
        .oneshot(as_owner(
            "PUT",
            &format!("/api/v1/agents/{}", keys.agent_id()),
            &owner.token,
            Some(&ConfirmAgentRequest { record: enc }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    record
}

async fn post_request(app: &App, owner: &Owner, keys: &RemoteKeys, method: &str) -> agent_remote::SealedRequest {
    let sealed = agent_remote::seal_request(keys, &owner.keys, method, json!({"item": "GitHub"}), now()).unwrap();
    let body = PostAgentRequest { id: sealed.id.clone(), request: sealed.request.clone() };
    let resp = app.clone().oneshot(agent(keys, "POST", "/api/v1/agent/requests", Some(&body))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    sealed
}

#[tokio::test]
async fn pair_confirm_ask_answer() {
    let (state, app) = setup();
    let alice = sign_up(&app, "alice@example.com").await;
    let (code, keys) = pair(&app, &alice, "Claude Code").await;

    // A pending agent may not ask yet.
    let sealed = agent_remote::seal_request(&keys, &alice.keys, "ping", json!({}), now()).unwrap();
    let body = PostAgentRequest { id: sealed.id.clone(), request: sealed.request.clone() };
    let resp = app.clone().oneshot(agent(&keys, "POST", "/api/v1/agent/requests", Some(&body))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_code(resp).await, "agent_not_confirmed");

    // The code is spent: pairing again with it fails.
    let proof = agent_remote::seal_proof(&code, &alice.keys, &keys, "x", "", None).unwrap();
    let again = PairAgentRequest { token: code.token(), keys: keys.public(), proof };
    let resp = app.clone().oneshot(agent(&keys, "POST", "/api/v1/agent/pair", Some(&again))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let record = confirm(&app, &alice, &code, &keys).await;
    // Every device opens the record and finds the keys the server lists.
    let resp = app.clone().oneshot(as_owner("GET", "/api/v1/agents", &alice.token, None::<&()>)).await.unwrap();
    let agents: Vec<AgentDto> = read(resp).await;
    let dto = &agents[0];
    assert!(dto.proof.is_none() && dto.token_hash.is_none(), "the proof is gone after confirming");
    let account_id = alice.session.account().id.clone();
    let opened = AgentRecordData::open(
        dto.record.as_ref().unwrap(),
        alice.session.account_key(),
        &account_id,
        &dto.id,
        &dto.keys,
    )
    .unwrap();
    assert_eq!(opened, record);

    // The agent asks; the owner sees a sealed request and opens it.
    let sealed = post_request(&app, &alice, &keys, "read").await;
    let resp =
        app.clone().oneshot(as_owner("GET", "/api/v1/agents/requests", &alice.token, None::<&()>)).await.unwrap();
    let open: Vec<AgentRequestDto> = read(resp).await;
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].id, sealed.id);
    assert_eq!(open[0].agent_id, keys.agent_id());
    let verified = record.keys.verify().unwrap();
    let request =
        agent_remote::open_request(alice.session.keyset(), &verified, &open[0].id, &open[0].request, now()).unwrap();
    assert_eq!(request.method, "read");
    assert_eq!(request.params["item"], "GitHub");

    // Meanwhile the agent sees it open.
    let path = format!("/api/v1/agent/requests/{}", sealed.id);
    let resp = app.clone().oneshot(agent(&keys, "GET", &path, None::<&()>)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(read::<AgentRequestStatus>(resp).await.status, AgentRequestState::Open);

    // The owner answers; the agent reads it once.
    let answer = agent_remote::seal_answer(&request.reply_key, &sealed.id, &Ok(json!({"value": "hunter2"}))).unwrap();
    let resp = app
        .clone()
        .oneshot(as_owner(
            "POST",
            &format!("/api/v1/agents/requests/{}/answer", sealed.id),
            &alice.token,
            Some(&AgentAnswerRequest { answer: answer.clone() }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    // A second answer is refused.
    let resp = app
        .clone()
        .oneshot(as_owner("POST", &format!("/api/v1/agents/requests/{}/deny", sealed.id), &alice.token, None::<&()>))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let resp = app.clone().oneshot(agent(&keys, "GET", &path, None::<&()>)).await.unwrap();
    let status: AgentRequestStatus = read(resp).await;
    assert_eq!(status.status, AgentRequestState::Answered);
    let value = agent_remote::open_answer(&sealed.reply_key, &sealed.id, status.answer.as_ref().unwrap()).unwrap();
    assert_eq!(value.unwrap()["value"], "hunter2");
    // Handed out once.
    let resp = app.clone().oneshot(agent(&keys, "GET", &path, None::<&()>)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp =
        app.clone().oneshot(as_owner("GET", "/api/v1/agents/requests", &alice.token, None::<&()>)).await.unwrap();
    assert!(read::<Vec<AgentRequestDto>>(resp).await.is_empty());

    // Denied.
    let sealed = post_request(&app, &alice, &keys, "otp").await;
    let resp = app
        .clone()
        .oneshot(as_owner("POST", &format!("/api/v1/agents/requests/{}/deny", sealed.id), &alice.token, None::<&()>))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let path = format!("/api/v1/agent/requests/{}", sealed.id);
    let resp = app.clone().oneshot(agent(&keys, "GET", &path, None::<&()>)).await.unwrap();
    assert_eq!(read::<AgentRequestStatus>(resp).await.status, AgentRequestState::Denied);

    // The database holds envelopes and keys, never the content.
    let dump: Vec<String> = state
        .db
        .run(|c| {
            let mut out = Vec::new();
            let mut stmt = c.prepare("SELECT record FROM agents")?;
            for row in stmt.query_map([], |r| r.get::<_, Option<String>>(0))? {
                out.extend(row?);
            }
            Ok(out)
        })
        .await
        .unwrap();
    assert!(dump.iter().all(|s| !s.contains("Claude Code") && !s.contains("hunter2")));
    assert_eq!(AgentError::NOT_CONFIRMED, -32009);
}

#[tokio::test]
async fn signatures_nonces_and_clocks() {
    let (_state, app) = setup();
    let alice = sign_up(&app, "alice@example.com").await;
    let (code, keys) = pair(&app, &alice, "Agent").await;
    confirm(&app, &alice, &code, &keys).await;
    let body = || {
        let sealed = agent_remote::seal_request(&keys, &alice.keys, "ping", json!({}), now()).unwrap();
        serde_json::to_vec(&PostAgentRequest { id: sealed.id, request: sealed.request }).unwrap()
    };
    let path = "/api/v1/agent/requests";

    // No header, a clock far off, a stranger's key, a replayed nonce.
    let resp = app
        .clone()
        .oneshot(Request::builder().method("POST").uri(path).body(Body::from(body())).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = app.clone().oneshot(agent_at(&keys, "POST", path, body(), now() - 600)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(resp).await, "agent_signature");
    let stranger = RemoteKeys::generate();
    let resp = app.clone().oneshot(agent_at(&stranger, "POST", path, body(), now())).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let bytes = body();
    let sig = HttpSignature::sign(&keys, "POST", path, &bytes, now());
    let signed = || {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header(HTTP_HEADER, sig.header())
            .body(Body::from(bytes.clone()))
            .unwrap()
    };
    let resp = app.clone().oneshot(signed()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let resp = app.clone().oneshot(signed()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "replayed nonce");
    // A signature over another body.
    let other = body();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(HTTP_HEADER, HttpSignature::sign(&keys, "POST", path, &other, now()).header())
                .body(Body::from(body()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // A signature over another path (the query counts).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/agent/requests/AAAAAAAAAAAAAAAAAAAAAA?wait=1")
                .header(
                    HTTP_HEADER,
                    HttpSignature::sign(&keys, "GET", "/api/v1/agent/requests/AAAAAAAAAAAAAAAAAAAAAA", b"", now())
                        .header(),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn limits_and_revocation() {
    let (state, app) = setup();
    let alice = sign_up(&app, "alice@example.com").await;
    let (code, keys) = pair(&app, &alice, "Agent").await;
    confirm(&app, &alice, &code, &keys).await;

    // At most two open requests (the test config).
    post_request(&app, &alice, &keys, "ping").await;
    post_request(&app, &alice, &keys, "ping").await;
    let sealed = agent_remote::seal_request(&keys, &alice.keys, "ping", json!({}), now()).unwrap();
    let body = PostAgentRequest { id: sealed.id.clone(), request: sealed.request.clone() };
    let resp = app.clone().oneshot(agent(&keys, "POST", "/api/v1/agent/requests", Some(&body))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Wrong pairing tokens.
    let resp = app
        .clone()
        .oneshot(Request::builder().uri("/api/v1/agent/pairing/nope").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let unknown = PairingCode::new("https://sync.example", &alice.keys).unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder().uri(format!("/api/v1/agent/pairing/{}", unknown.token())).body(Body::empty()).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(error_code(resp).await, "pairing_invalid");

    // An expired code is cleaned up and no longer works.
    let resp = app
        .clone()
        .oneshot(as_owner(
            "POST",
            "/api/v1/agents/pairings",
            &alice.token,
            Some(&CreatePairingRequest { token_hash: unknown.token_hash() }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let later = now() + PAIRING_SECONDS + 1;
    state.db.run(move |c| Ok(twosecret_server::agents::delete_expired(c, later)?)).await.unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder().uri(format!("/api/v1/agent/pairing/{}", unknown.token())).body(Body::empty()).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Another account cannot see or answer Alice's requests.
    let bob = sign_up(&app, "bob@example.com").await;
    let resp = app.clone().oneshot(as_owner("GET", "/api/v1/agents/requests", &bob.token, None::<&()>)).await.unwrap();
    assert!(read::<Vec<AgentRequestDto>>(resp).await.is_empty());
    let resp = app.clone().oneshot(as_owner("GET", "/api/v1/agents", &bob.token, None::<&()>)).await.unwrap();
    assert!(read::<Vec<AgentDto>>(resp).await.is_empty());
    let resp = app
        .clone()
        .oneshot(as_owner("POST", &format!("/api/v1/agents/requests/{}/deny", sealed.id), &bob.token, None::<&()>))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = app
        .clone()
        .oneshot(as_owner("DELETE", &format!("/api/v1/agents/{}", keys.agent_id()), &bob.token, None::<&()>))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Expired requests go.
    let later = now() + REQUEST_SECONDS + 1;
    state.db.run(move |c| Ok(twosecret_server::agents::delete_expired(c, later)?)).await.unwrap();
    let resp =
        app.clone().oneshot(as_owner("GET", "/api/v1/agents/requests", &alice.token, None::<&()>)).await.unwrap();
    assert!(read::<Vec<AgentRequestDto>>(resp).await.is_empty());

    // Revoked: the agent's open requests go and it is told.
    post_request(&app, &alice, &keys, "ping").await;
    let resp = app
        .clone()
        .oneshot(as_owner("DELETE", &format!("/api/v1/agents/{}", keys.agent_id()), &alice.token, None::<&()>))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = app.clone().oneshot(as_owner("GET", "/api/v1/agents", &alice.token, None::<&()>)).await.unwrap();
    assert!(read::<Vec<AgentDto>>(resp).await.is_empty());
    let resp =
        app.clone().oneshot(as_owner("GET", "/api/v1/agents/requests", &alice.token, None::<&()>)).await.unwrap();
    assert!(read::<Vec<AgentRequestDto>>(resp).await.is_empty());
    let resp = app.clone().oneshot(agent(&keys, "POST", "/api/v1/agent/requests", Some(&body))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_code(resp).await, "agent_revoked");

    // The same agent can pair again with a new code.
    let (code, keys2) = pair(&app, &alice, "Agent").await;
    assert_ne!(keys2.agent_id(), keys.agent_id(), "new keys per pairing");
    confirm(&app, &alice, &code, &keys2).await;
}

#[tokio::test]
async fn long_polls_are_woken() {
    let (_state, app) = setup();
    let alice = sign_up(&app, "alice@example.com").await;
    let (code, keys) = pair(&app, &alice, "Agent").await;
    confirm(&app, &alice, &code, &keys).await;

    // The owner waits; a request arrives after half a second.
    let waiting = tokio::spawn({
        let app = app.clone();
        let token = alice.token.clone();
        async move {
            let started = Instant::now();
            let resp =
                app.oneshot(as_owner("GET", "/api/v1/agents/requests?wait=10", &token, None::<&()>)).await.unwrap();
            (read::<Vec<AgentRequestDto>>(resp).await, started.elapsed())
        }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let sealed = post_request(&app, &alice, &keys, "ping").await;
    let (requests, took) = waiting.await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(took < Duration::from_secs(5), "woken by the request, took {took:?}");

    // The agent waits; the answer arrives after half a second.
    let waiting = tokio::spawn({
        let app = app.clone();
        let path = format!("/api/v1/agent/requests/{}?wait=10", sealed.id);
        let req = agent(&keys, "GET", &path, None::<&()>);
        async move {
            let started = Instant::now();
            let resp = app.oneshot(req).await.unwrap();
            (read::<AgentRequestStatus>(resp).await, started.elapsed())
        }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let resp = app
        .clone()
        .oneshot(as_owner("POST", &format!("/api/v1/agents/requests/{}/deny", sealed.id), &alice.token, None::<&()>))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let (status, took) = waiting.await.unwrap();
    assert_eq!(status.status, AgentRequestState::Denied);
    assert!(took < Duration::from_secs(5), "woken by the answer, took {took:?}");

    // Nothing to wait for: `wait=1` returns empty after about a second.
    let started = Instant::now();
    let resp = app
        .clone()
        .oneshot(as_owner("GET", "/api/v1/agents/requests?wait=1", &alice.token, None::<&()>))
        .await
        .unwrap();
    assert!(read::<Vec<AgentRequestDto>>(resp).await.is_empty());
    assert!(started.elapsed() >= Duration::from_millis(900));
}
