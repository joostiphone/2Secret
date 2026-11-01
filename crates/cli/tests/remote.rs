//! An agent on another computer: `2secret agent pair` with the real binary,
//! the owner confirming (as the app does), `2secret mcp --remote` asking
//! through the relay and the owner's 2Secret answering, then revocation.
//! The server in between sees envelopes only.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use assert_cmd::Command;
use serde_json::{json, Value};
use twosecret_core::agent::{self, Request};
use twosecret_core::agent_remote::{self, AgentRecordData, PairingCode};
use twosecret_core::crypto::KdfParams;
use twosecret_core::session::Session;
use twosecret_core::util::now;
use twosecret_core::Item;
use twosecret_server::{AppState, Config};

const PW: &str = "Vq8#mT2!zL5@pR9$";

fn temp_home(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("2secret-remote-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cli(home: &Path) -> Command {
    let mut c = Command::cargo_bin("2secret").unwrap();
    c.env("TWOSECRET_HOME", home)
        .env("TWOSECRET_INSECURE_TEST_KDF", "1")
        .env("HOSTNAME", "build-1")
        .env_remove("TWOSECRET_SESSION")
        .env_remove("TWOSECRET_PASSWORD");
    c
}

async fn start_server() -> (String, AppState) {
    let state = AppState::in_memory(Config::default()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let served = state.clone();
    tokio::spawn(async move {
        let _ = twosecret_server::serve(listener, served).await;
    });
    (format!("http://{addr}"), state)
}

fn mcp_lines(calls: &[(u64, &str, Value)]) -> String {
    let mut lines = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"test-client","version":"0.1"}}})
        .to_string(),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string(),
    ];
    for (id, tool, arguments) in calls {
        lines.push(
            json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":arguments}})
                .to_string(),
        );
    }
    lines.join("\n") + "\n"
}

/// The answers of `2secret mcp`, by request id: the tool text and whether
/// it was an error.
fn answers(stdout: &[u8]) -> Vec<(u64, String, bool)> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .map(|v| {
            let result = &v["result"];
            (
                v["id"].as_u64().unwrap_or_default(),
                result["content"][0]["text"].as_str().unwrap_or_default().to_string(),
                result["isError"].as_bool().unwrap_or(false),
            )
        })
        .collect()
}

/// The owner's 2Secret: fetches requests, allows everything but one-time
/// codes, and answers. Stops when `stop` is set.
fn owner_app(session: Arc<Mutex<Session>>, stop: Arc<AtomicBool>) -> tokio::task::JoinHandle<Vec<String>> {
    tokio::spawn(async move {
        let mut seen = Vec::new();
        let client = twosecret_client::client_for(&session.lock().unwrap()).unwrap();
        let dtos = client.agents().await.unwrap();
        let agents: Vec<_> = {
            let s = session.lock().unwrap();
            dtos.into_iter()
                .filter_map(|d| {
                    let record =
                        AgentRecordData::open(d.record.as_ref()?, s.account_key(), &s.account().id, &d.id, &d.keys)
                            .ok()?;
                    Some((d.id, record.keys.verify().unwrap()))
                })
                .collect()
        };
        while !stop.load(Ordering::SeqCst) {
            let requests = match client.agent_requests(3).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            for r in requests {
                let Some((_, keys)) = agents.iter().find(|(id, _)| *id == r.agent_id) else { continue };
                let opened = {
                    let s = session.lock().unwrap();
                    agent_remote::open_request(s.keyset(), keys, &r.id, &r.request, now()).unwrap()
                };
                seen.push(opened.method.clone());
                let outcome = match Request::parse(&opened.method, Some(opened.params)) {
                    Ok(Request::Otp(_)) => Err(agent::AgentError::denied()),
                    Ok(request) => agent::execute(&session.lock().unwrap(), &request),
                    Err(e) => Err(e),
                };
                let answer = agent_remote::seal_answer(&opened.reply_key, &r.id, &outcome).unwrap();
                let _ = client.answer_agent_request(&r.id, answer).await;
            }
        }
        seen
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pair_ask_and_revoke_through_the_relay() {
    let (url, state) = start_server().await;
    let (mut owner, _sk) = twosecret_client::signup(
        &url,
        "Alice",
        "alice@example.com",
        PW,
        None,
        "laptop",
        "Personal",
        KdfParams::insecure_for_tests(),
    )
    .await
    .unwrap();
    let vault = owner.default_vault_id().unwrap();
    owner.add_item(&vault, Item::login("GitHub", "octo", "hunter2", Some("https://github.com"))).unwrap();
    let client = twosecret_client::client_for(&owner).unwrap();

    // The app makes a code and registers it.
    let code = PairingCode::new(&url, &owner.public_keys()).unwrap();
    client.create_agent_pairing(&code.token_hash()).await.unwrap();

    // The agent's computer pairs with the link.
    let home = temp_home("agent");
    let out = cli(&home).args(["agent", "pair", &code.uri(), "--name", "Build server"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Fingerprint:") && text.contains("2secret mcp --remote"), "{text}");
    assert!(home.join("remote-build-server.json").is_file());
    let status: Value =
        serde_json::from_slice(&cli(&home).args(["--json", "agent", "status"]).output().unwrap().stdout).unwrap();
    assert_eq!(status["pairings"][0]["name"], "Build server");
    let fingerprint = status["pairings"][0]["fingerprint"].as_str().unwrap().to_string();
    let agent_id = status["pairings"][0]["agent_id"].as_str().unwrap().to_string();
    assert_eq!(status["pairings"][0]["account_fingerprint"], owner.public_keys().fingerprint());

    // The code is spent: pairing again fails and says so.
    let again = cli(&home).args(["agent", "pair", &code.uri(), "--name", "Again"]).output().unwrap();
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("not valid"));

    // Not confirmed yet: the agent is told.
    let out = cli(&home)
        .args(["mcp", "--remote", "Build server"])
        .write_stdin(mcp_lines(&[(2, "search_items", json!({"query": "git"}))]))
        .output()
        .unwrap();
    let early = answers(&out.stdout);
    assert!(early[1].2 && early[1].1.contains("not confirmed"), "{:?}", early);

    // The owner confirms, after checking the proof (as the app does).
    let dto = client
        .agents()
        .await
        .unwrap()
        .into_iter()
        .find(|a| a.token_hash.as_deref() == Some(code.token_hash().as_str()))
        .expect("pending agent listed");
    assert_eq!(dto.id, agent_id);
    let proof =
        agent_remote::open_proof(owner.keyset(), dto.token_hash.as_deref().unwrap(), dto.proof.as_ref().unwrap())
            .unwrap();
    proof.check(&code, &dto.keys).unwrap();
    assert_eq!(proof.name, "Build server");
    assert_eq!(proof.device.as_deref(), Some("build-1"));
    assert_eq!(dto.keys.fingerprint().unwrap(), fingerprint, "the CLI shows the fingerprint the app shows");
    let record = AgentRecordData {
        name: proof.name.clone(),
        version: proof.version.clone(),
        keys: dto.keys.clone(),
        fingerprint: fingerprint.clone(),
        paired_at: now(),
        device: proof.device.clone(),
        paired_on: Some("laptop".into()),
    };
    let enc = record.seal(owner.account_key(), &owner.account().id, &dto.id).unwrap();
    client.confirm_agent(&dto.id, enc).await.unwrap();

    // The owner's 2Secret answers in the background while the agent asks.
    let session = Arc::new(Mutex::new(owner));
    let stop = Arc::new(AtomicBool::new(false));
    let app = owner_app(session.clone(), stop.clone());
    let out = tokio::task::spawn_blocking({
        let home = home.clone();
        move || {
            cli(&home)
                .args(["mcp", "--remote", "Build server"])
                .write_stdin(mcp_lines(&[
                    (2, "search_items", json!({"query": "git"})),
                    (3, "read_field", json!({"item": "GitHub", "field": "password"})),
                    (4, "get_otp", json!({"item": "GitHub"})),
                    (5, "agent_status", json!({})),
                ]))
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();
    stop.store(true, Ordering::SeqCst);
    let seen = app.await.unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let got = answers(&out.stdout);
    assert_eq!(got.len(), 5, "{got:?}");
    let initialize: Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).lines().next().unwrap()).unwrap();
    assert!(initialize["result"]["instructions"].as_str().unwrap().contains("sync server"));
    assert!(!got[1].2 && got[1].1.contains("GitHub") && !got[1].1.contains("hunter2"), "{:?}", got[1]);
    assert_eq!((got[2].1.as_str(), got[2].2), ("hunter2", false));
    assert!(got[3].2 && got[3].1.contains("did not allow"), "{:?}", got[3]);
    let status: Value = serde_json::from_str(&got[4].1).unwrap();
    assert_eq!(status["mode"], "remote");
    assert_eq!(status["paired"], true);
    assert_eq!(status["fingerprint"], fingerprint);
    assert_eq!(seen, ["search", "read", "otp"]);

    // The server held envelopes and public keys, never names or values.
    let rows: Vec<String> = state
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
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].contains("Build server") && !rows[0].contains("hunter2"));

    // Revoked by the owner: the agent hears it.
    client.revoke_agent(&agent_id).await.unwrap();
    let out = cli(&home)
        .args(["mcp", "--remote"])
        .write_stdin(mcp_lines(&[(2, "search_items", json!({"query": "git"}))]))
        .output()
        .unwrap();
    let got = answers(&out.stdout);
    assert!(got[1].2 && got[1].1.contains("revoked"), "{:?}", got);

    // Forgotten here.
    cli(&home).args(["agent", "unpair"]).assert().success();
    assert!(!home.join("remote-build-server.json").exists());
    let status: Value =
        serde_json::from_slice(&cli(&home).args(["--json", "agent", "status"]).output().unwrap().stdout).unwrap();
    assert!(status["pairings"].as_array().unwrap().is_empty());
    let out = cli(&home)
        .args(["mcp", "--remote"])
        .write_stdin(mcp_lines(&[(2, "search_items", json!({"query": "git"}))]))
        .output()
        .unwrap();
    let got = answers(&out.stdout);
    assert!(got[1].2 && got[1].1.contains("not paired"), "{:?}", got);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn bad_codes_are_refused() {
    let home = temp_home("codes");
    let out = cli(&home).args(["agent", "pair", "2A-NOT-A-CODE"]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("pairing code"));
    let out = cli(&home).args(["agent", "unpair"]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not paired"));
    let _ = std::fs::remove_dir_all(&home);
}
