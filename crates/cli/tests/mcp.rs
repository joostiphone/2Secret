//! `2secret mcp` against a fake desktop app on the Agent Access socket, and
//! `2secret mcp --standalone` on a local vault.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::{json, Value};
use twosecret_core::agent::{verify_hello, AgentError};
use twosecret_core::util::{b64, random_bytes, unb64};

const PW: &str = "Vq8#mT2!zL5@pR9$";

fn temp_home(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("2secret-mcp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cli(home: &Path) -> Command {
    let mut c = Command::cargo_bin("2secret").unwrap();
    c.env("TWOSECRET_HOME", home)
        .env("TWOSECRET_INSECURE_TEST_KDF", "1")
        .env("TWOSECRET_PASSWORD", PW)
        .env_remove("TWOSECRET_SESSION");
    c
}

fn lines(messages: &[Value]) -> String {
    messages.iter().map(|m| m.to_string() + "\n").collect()
}

fn initialize() -> Vec<Value> {
    vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"test-client","version":"0.1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    ]
}

fn call(id: u64, tool: &str, arguments: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":arguments}})
}

/// The answers of `2secret mcp`, one per request id.
fn answers(stdout: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn tool_text(answer: &Value) -> (String, bool) {
    let result = &answer["result"];
    (
        result["content"][0]["text"].as_str().unwrap_or_default().to_string(),
        result["isError"].as_bool().unwrap_or(false),
    )
}

/// What the fake app saw.
#[derive(Default)]
struct Seen {
    hello: Option<Value>,
    methods: Vec<String>,
}

/// A stand-in for the desktop app: pairs any agent whose signature checks
/// out, knows one item, refuses to reveal its password, and hands out the
/// values of references for `run_command`.
fn fake_app(home: &Path) -> Arc<Mutex<Seen>> {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let listener = UnixListener::bind(home.join("access.sock")).unwrap();
    let state = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let state = state.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut writer = stream;
                let mut line = String::new();
                let mut key: Option<String> = None;
                let mut nonce: Option<Vec<u8>> = None;
                while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                    let msg: Value = serde_json::from_str(&line).unwrap();
                    line.clear();
                    let id = msg["id"].clone();
                    let method = msg["method"].as_str().unwrap_or_default().to_string();
                    let params = msg["params"].clone();
                    state.lock().unwrap().methods.push(method.clone());
                    let answer = match method.as_str() {
                        "hello" => {
                            state.lock().unwrap().hello = Some(params.clone());
                            key = params["agent_key"].as_str().map(str::to_string);
                            let n = random_bytes::<32>().to_vec();
                            nonce = Some(n.clone());
                            Ok(json!({"protocol": 1, "app_version": "test", "nonce": b64(&n)}))
                        }
                        "auth" => {
                            let sig = params["signature"].as_str().unwrap_or_default();
                            match verify_hello(
                                key.as_deref().unwrap_or_default(),
                                nonce.as_deref().unwrap_or_default(),
                                sig,
                            ) {
                                Ok(id) => Ok(json!({"agent_id": id, "state": "paired"})),
                                Err(e) => Err(AgentError::new(AgentError::DENIED, e.to_string())),
                            }
                        }
                        "ping" => Ok(json!({})),
                        "search" => Ok(json!({"items": [{"id": "item-1", "vault_id": "v", "vault": "Personal",
                            "category": "login", "title": "GitHub", "username": "octo", "urls": ["https://github.com"],
                            "favorite": false, "has_password": true, "has_totp": false, "has_notes": false,
                            "updated_at": 0, "fields": []}]})),
                        "read" => Err(AgentError::denied()),
                        "fill" => {
                            if params["url"].as_str().is_some_and(|u| u.contains("github.com")) {
                                Ok(json!({"filled": true, "browser": "chrome", "submitted": params["submit"] != false}))
                            } else {
                                Err(AgentError::new(AgentError::NOT_FOUND, "'GitHub' is not a login for example.com"))
                            }
                        }
                        "status" => Ok(json!({"app_version": "test", "browsers": [{"browser": "chrome",
                            "extension": "chrome-extension://gnkfgnlegljjfnihdefkjepdoaphccfd/", "version": "1.11.0", "since": 1}]})),
                        "read_many" => {
                            let values: serde_json::Map<String, Value> = params["refs"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|r| (r.as_str().unwrap().to_string(), json!("hunter2")))
                                .collect();
                            Ok(json!({"values": values}))
                        }
                        other => Err(AgentError::method_not_found(other)),
                    };
                    let reply = match answer {
                        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
                        Err(e) => json!({"jsonrpc": "2.0", "id": id, "error": e}),
                    };
                    let _ = writer.write_all((reply.to_string() + "\n").as_bytes());
                }
            });
        }
    });
    seen
}

#[test]
fn mcp_talks_to_the_app() {
    let home = temp_home("app");
    let seen = fake_app(&home);
    let mut messages = initialize();
    messages.push(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    messages.push(call(3, "search_items", json!({"query": "github"})));
    messages.push(call(4, "read_field", json!({"item": "GitHub", "field": "password"})));
    messages.push(call(
        5,
        "run_command",
        json!({"command": ["sh", "-c", "echo pw=$X; echo err=$X >&2"], "env": {"X": "2s://Personal/Db/password"}}),
    ));
    messages.push(call(6, "agent_status", json!({})));
    messages.push(json!({"jsonrpc":"2.0","id":7,"method":"ping"}));
    messages.push(json!({"jsonrpc":"2.0","id":8,"method":"nope"}));
    messages.push(call(9, "fill_login", json!({"item": "GitHub", "url": "https://github.com/login"})));
    messages.push(call(10, "fill_login", json!({"item": "GitHub", "url": "https://example.com/login"})));

    let output = cli(&home).args(["mcp"]).write_stdin(lines(&messages)).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(!out.contains("hunter2"), "the secret must not reach the model:\n{out}");
    let answers = answers(&output.stdout);
    assert_eq!(answers.len(), 10, "{out}");

    assert_eq!(answers[0]["id"], 1);
    assert_eq!(answers[0]["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(answers[0]["result"]["serverInfo"]["name"], "2secret");
    assert!(answers[0]["result"]["capabilities"]["tools"].is_object());

    let tools = answers[1]["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"search_items") && names.contains(&"read_field") && names.contains(&"run_command"));

    let (text, is_error) = tool_text(&answers[2]);
    assert!(!is_error && text.contains("GitHub") && text.contains("octo"), "{text}");

    let (text, is_error) = tool_text(&answers[3]);
    assert!(is_error && text.contains("did not allow"), "{text}");

    let (text, is_error) = tool_text(&answers[4]);
    assert!(!is_error, "{text}");
    let run: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(run["exit_code"], 0);
    assert_eq!(run["stdout"].as_str().unwrap().trim(), "pw=«2s://Personal/Db/password»");
    assert_eq!(run["stderr"].as_str().unwrap().trim(), "err=«2s://Personal/Db/password»");

    let (text, is_error) = tool_text(&answers[5]);
    assert!(!is_error, "{text}");
    let status: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(status["connected"], true);
    assert_eq!(status["agent_name"], "test-client");
    assert!(status["agent_id"].as_str().unwrap().len() == 19);
    assert_eq!(status["browsers"][0]["browser"], "chrome", "{status}");

    assert_eq!(answers[6]["id"], 7);
    assert!(answers[6]["result"].is_object());
    // Unknown methods are refused, which still counts as an answer.
    assert_eq!(answers[7]["id"], 8);
    assert_eq!(answers[7]["error"]["code"], -32601);

    let (text, is_error) = tool_text(&answers[8]);
    assert!(!is_error, "{text}");
    let filled: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(filled["filled"], true);
    assert_eq!(filled["browser"], "chrome");
    let (text, is_error) = tool_text(&answers[9]);
    assert!(is_error && text.contains("not a login for example.com"), "{text}");

    let seen = seen.lock().unwrap();
    let hello = seen.hello.as_ref().expect("the agent introduced itself");
    assert_eq!(hello["name"], "test-client", "the MCP client's name is what the app shows");
    assert_eq!(hello["version"], "0.1");
    assert_eq!(hello["protocol"], 1);
    assert!(unb64(hello["agent_key"].as_str().unwrap()).unwrap().len() == 32);
    assert_eq!(seen.methods.iter().filter(|m| *m == "hello").count(), 1, "one connection for the whole session");
    assert!(seen.methods.contains(&"read_many".to_string()));
    assert_eq!(seen.methods.iter().filter(|m| *m == "fill").count(), 2);

    // The key stays, so the app knows the agent next time.
    assert!(home.join("agent-key-test-client.json").exists());
    cli(&home).args(["agent", "status"]).assert().success().stdout(
        predicate::str::contains("reachable for agents")
            .and(predicate::str::contains("test-client"))
            .and(predicate::str::contains("Browsers:")),
    );
}

#[test]
fn mcp_without_the_app_explains() {
    let home = temp_home("noapp");
    let mut messages = initialize();
    messages.push(call(2, "search_items", json!({})));
    let output = cli(&home).args(["mcp"]).write_stdin(lines(&messages)).output().unwrap();
    assert!(output.status.success());
    let answers = answers(&output.stdout);
    let (text, is_error) = tool_text(&answers[1]);
    assert!(is_error && text.contains("not running"), "{text}");
    cli(&home).args(["agent", "status"]).assert().success().stdout(predicate::str::contains("not reachable"));
}

#[test]
fn standalone_only_searches_and_generates() {
    let home = temp_home("standalone");
    cli(&home)
        .args(["account", "create", "--name", "Test", "--email", "test@example.com"])
        .env_remove("TWOSECRET_PASSWORD")
        .write_stdin(format!("{PW}\n{PW}\n"))
        .assert()
        .success();
    cli(&home)
        .args([
            "add",
            "login",
            "--title",
            "GitHub",
            "--username",
            "octo",
            "--password",
            "hunter2hunter2",
            "--url",
            "https://github.com",
        ])
        .assert()
        .success();

    let mut messages = initialize();
    messages.push(call(2, "search_items", json!({"query": "git"})));
    messages.push(call(3, "read_field", json!({"item": "GitHub", "field": "password"})));
    messages.push(call(4, "generate_password", json!({"length": 16})));
    messages.push(call(5, "run_command", json!({"command": ["true"]})));
    messages.push(call(6, "get_item", json!({"item": "GitHub"})));
    let output = cli(&home).args(["mcp", "--standalone"]).write_stdin(lines(&messages)).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(!out.contains("hunter2"), "{out}");
    let answers = answers(&output.stdout);
    let (text, is_error) = tool_text(&answers[1]);
    assert!(!is_error && text.contains("GitHub"), "{text}");
    let (text, is_error) = tool_text(&answers[2]);
    assert!(is_error && text.contains("desktop app"), "{text}");
    let (text, is_error) = tool_text(&answers[3]);
    assert!(!is_error);
    let generated: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(generated["value"].as_str().unwrap().len(), 16);
    let (text, is_error) = tool_text(&answers[4]);
    assert!(is_error && text.contains("turned off"), "{text}");
    let (text, is_error) = tool_text(&answers[5]);
    assert!(!is_error && text.contains("\"secret\":true"), "{text}");

    // With --allow-run the program gets the value, the model the reference.
    let mut messages = initialize();
    messages.push(call(
        2,
        "run_command",
        json!({"command": ["sh", "-c", "echo $P"], "env": {"P": "2s://GitHub/password"}}),
    ));
    let output =
        cli(&home).args(["mcp", "--standalone", "--allow-run"]).write_stdin(lines(&messages)).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(!out.contains("hunter2"), "{out}");
    assert!(out.contains("«2s://GitHub/password»"), "{out}");
}
