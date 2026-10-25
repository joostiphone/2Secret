//! The MCP tools: what an AI client sees and calls. Each tool maps to one
//! request to the app ([`Backend::call`]); `run_command` runs a program
//! with secrets in its environment and filters them out of the output.

use std::collections::BTreeMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};
use twosecret_core::agent::ReadManyResult;
use twosecret_core::secret_ref;

use crate::scrub::{scrub, truncate};

/// Where tool calls go: the running app, or (standalone) the vault itself.
pub trait Backend {
    /// One request of the agent protocol; the error is text for the model.
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String>;
    /// For `agent_status`.
    fn status(&mut self) -> Value;
    /// Whether `run_command` may run programs.
    fn may_run(&self) -> bool;
}

/// What a tool returns to the model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolResult {
    pub text: String,
    pub is_error: bool,
}

impl ToolResult {
    fn ok(text: impl Into<String>) -> Self {
        Self { text: text.into(), is_error: false }
    }
    fn err(text: impl Into<String>) -> Self {
        Self { text: text.into(), is_error: true }
    }
    fn json(value: &Value) -> Self {
        Self::ok(serde_json::to_string(value).unwrap_or_default())
    }
}

const ITEM_DESC: &str = "Item id (from search_items), its exact title, or a 2s:// reference (2s://vault/item/field).";

/// The tool list for `tools/list`.
pub fn definitions() -> Vec<Value> {
    let item = json!({ "type": "string", "description": ITEM_DESC });
    let field_list = json!({
        "type": "array",
        "description": "Extra fields to set; label matches an existing field or creates one.",
        "items": { "type": "object", "additionalProperties": false, "required": ["label", "value"], "properties": {
            "label": { "type": "string" },
            "value": { "type": "string" },
            "secret": { "type": "boolean", "description": "Store concealed, like a password." }
        } }
    });
    vec![
        tool(
            "search_items",
            "Find items in the user's 2Secret vaults. Returns titles, user names, websites, tags and which fields \
             exist, never passwords, one-time codes or notes. No approval needed.",
            json!({ "type": "object", "additionalProperties": false, "properties": {
                "query": { "type": "string", "description": "Words in the title, user name, website or tags." },
                "url": { "type": "string", "description": "Only items for this website, matched like autofill." },
                "vault": { "type": "string", "description": "Vault name or id." },
                "category": { "type": "string", "description": "Item type, e.g. login, api_credential, ssh_key, database, server, credit_card." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 100 }
            } }),
            true,
        ),
        tool(
            "get_item",
            "One item without its secrets: fields are listed with secret: true and no value. No approval needed.",
            json!({ "type": "object", "additionalProperties": false, "required": ["item"], "properties": { "item": item } }),
            true,
        ),
        tool(
            "read_field",
            "Read one value of an item: a password, an API key, a custom field, the notes, or 'otp' for the current \
             one-time code. The user has to approve it in 2Secret, and the value becomes visible to you in this \
             conversation. Prefer run_command with 2s:// references when a program needs the secret, not you.",
            json!({ "type": "object", "additionalProperties": false, "required": ["item"], "properties": {
                "item": item,
                "field": { "type": "string", "description": "Field id or label, or username, password, otp, url, notes, title. May be left out when item is a 2s:// reference." },
                "reason": { "type": "string", "maxLength": 200, "description": "Why you need it; shown to the user." }
            } }),
            true,
        ),
        tool(
            "get_otp",
            "The current one-time code (TOTP) of an item, with the seconds it stays valid. The user approves in 2Secret.",
            json!({ "type": "object", "additionalProperties": false, "required": ["item"], "properties": { "item": item } }),
            true,
        ),
        tool(
            "generate_password",
            "Generate a strong random password, a memorable passphrase (words) or a PIN (pin). No approval needed; nothing is stored.",
            json!({ "type": "object", "additionalProperties": false, "properties": {
                "length": { "type": "integer", "minimum": 8, "maximum": 128, "description": "Characters of a random password (default 20)." },
                "words": { "type": "integer", "minimum": 3, "maximum": 10, "description": "Words of a passphrase instead." },
                "pin": { "type": "integer", "minimum": 4, "maximum": 12, "description": "Digits of a PIN instead." },
                "symbols": { "type": "boolean" },
                "digits": { "type": "boolean" },
                "uppercase": { "type": "boolean" },
                "lowercase": { "type": "boolean" },
                "avoid_ambiguous": { "type": "boolean", "description": "Leave out l, 1, O, 0 and the like." }
            } }),
            true,
        ),
        tool(
            "save_login",
            "Save a new item (a login by default) in the user's vault. With generate_password 2Secret makes the \
             password itself and you never see it. The user approves in 2Secret.",
            json!({ "type": "object", "additionalProperties": false, "required": ["title"], "properties": {
                "title": { "type": "string" },
                "vault": { "type": "string", "description": "Vault name or id; the default vault when left out." },
                "category": { "type": "string", "description": "login (default), api_credential, password, secure_note, ssh_key, database, server, …" },
                "username": { "type": "string" },
                "password": { "type": "string" },
                "generate_password": { "type": "boolean" },
                "url": { "type": "string" },
                "notes": { "type": "string" },
                "tags": { "type": "array", "items": { "type": "string" } },
                "fields": field_list,
                "reason": { "type": "string", "maxLength": 200 }
            } }),
            false,
        ),
        tool(
            "update_item",
            "Change an existing item: title, user name, password, notes, add websites or set fields. The user approves in 2Secret.",
            json!({ "type": "object", "additionalProperties": false, "required": ["item"], "properties": {
                "item": item,
                "set": { "type": "object", "additionalProperties": false, "properties": {
                    "title": { "type": "string" }, "username": { "type": "string" },
                    "password": { "type": "string" }, "notes": { "type": "string" }
                } },
                "add_urls": { "type": "array", "items": { "type": "string" } },
                "fields": field_list,
                "reason": { "type": "string", "maxLength": 200 }
            } }),
            false,
        ),
        tool(
            "run_command",
            "Run a program with secrets in its environment without seeing them: give environment variables whose \
             value is a 2s:// reference (2s://vault/item/field, fields include username, password, otp). 2Secret asks the \
             user once for all references, the program gets the real values, and the values are replaced by their \
             references in the output you get back. Output is cut at 64 KiB per stream.",
            json!({ "type": "object", "additionalProperties": false, "required": ["command"], "properties": {
                "command": { "type": "array", "minItems": 1, "items": { "type": "string" }, "description": "Program and arguments." },
                "env": { "type": "object", "additionalProperties": { "type": "string" }, "description": "Environment variables; a value may be a 2s:// reference." },
                "cwd": { "type": "string" },
                "timeout_secs": { "type": "integer", "minimum": 1, "maximum": 600, "description": "Default 120." }
            } }),
            false,
        ),
        tool(
            "agent_status",
            "Whether 2Secret is reachable, as which agent this connection is known, and where it listens. For troubleshooting.",
            json!({ "type": "object", "additionalProperties": false, "properties": {} }),
            true,
        ),
    ]
}

fn tool(name: &str, description: &str, schema: Value, read_only: bool) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": schema,
        "annotations": { "readOnlyHint": read_only, "destructiveHint": false, "openWorldHint": false }
    })
}

/// Run one tool.
pub fn call_tool(backend: &mut dyn Backend, name: &str, args: Value) -> ToolResult {
    let args = if args.is_null() { json!({}) } else { args };
    if !args.is_object() {
        return ToolResult::err("arguments must be an object");
    }
    match name {
        "search_items" => forward(backend, "search", args),
        "get_item" => forward(backend, "item", args),
        "read_field" => match backend.call("read", args) {
            Ok(v) => ToolResult::ok(v.get("value").and_then(Value::as_str).unwrap_or_default()),
            Err(e) => ToolResult::err(e),
        },
        "get_otp" => forward(backend, "otp", args),
        "generate_password" => forward(backend, "generate", args),
        "save_login" => {
            let mut args = args;
            if let Some(o) = args.as_object_mut() {
                if let Some(g) = o.remove("generate_password") {
                    o.insert("generate".into(), g);
                }
            }
            forward(backend, "create_item", args)
        }
        "update_item" => forward(backend, "update_item", args),
        "run_command" => run_command(backend, args),
        "agent_status" => ToolResult::json(&backend.status()),
        other => ToolResult::err(format!("unknown tool '{other}'")),
    }
}

fn forward(backend: &mut dyn Backend, method: &str, args: Value) -> ToolResult {
    match backend.call(method, args) {
        Ok(v) => ToolResult::json(&v),
        Err(e) => ToolResult::err(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunArgs {
    command: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

fn run_command(backend: &mut dyn Backend, args: Value) -> ToolResult {
    let args: RunArgs = match serde_json::from_value(args) {
        Ok(a) => a,
        Err(e) => return ToolResult::err(format!("invalid arguments: {e}")),
    };
    if args.command.is_empty() || args.command[0].trim().is_empty() {
        return ToolResult::err("command is empty");
    }
    if !backend.may_run() {
        return ToolResult::err(
            "running programs is turned off here (start `2secret mcp` without --standalone, or with --allow-run)",
        );
    }
    let refs: Vec<String> = args.env.values().filter(|v| secret_ref::is_reference(v)).cloned().collect();
    let mut secrets: Vec<(String, String)> = Vec::new();
    if !refs.is_empty() {
        let shown: String = args.command.join(" ").chars().take(120).collect();
        let answer = match backend.call("read_many", json!({ "refs": refs, "reason": format!("run {shown}") })) {
            Ok(v) => v,
            Err(e) => return ToolResult::err(e),
        };
        let values: ReadManyResult = match serde_json::from_value(answer) {
            Ok(v) => v,
            Err(e) => return ToolResult::err(format!("unexpected answer from 2Secret: {e}")),
        };
        secrets = values.values.into_iter().collect();
    }
    let mut cmd = Command::new(&args.command[0]);
    cmd.args(&args.command[1..]);
    if let Some(dir) = &args.cwd {
        cmd.current_dir(dir);
    }
    for (k, v) in &args.env {
        if secret_ref::is_reference(v) {
            match secrets.iter().find(|(r, _)| r == v) {
                Some((_, value)) => cmd.env(k, value),
                None => return ToolResult::err(format!("no value for {v}")),
            };
        } else {
            cmd.env(k, v);
        }
    }
    cmd.env_remove("TWOSECRET_PASSWORD").env_remove("TWOSECRET_SESSION");
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return ToolResult::err(format!("could not run '{}': {e}", args.command[0])),
    };
    let read_all = |stream: Option<std::process::ChildStdout>| -> Vec<u8> {
        let mut buf = Vec::new();
        if let Some(mut s) = stream {
            let _ = s.read_to_end(&mut buf);
        }
        buf
    };
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let out_thread = std::thread::spawn(move || read_all(stdout));
    let err_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut s) = stderr {
            let _ = s.read_to_end(&mut buf);
        }
        buf
    });
    let timeout = Duration::from_secs(args.timeout_secs.unwrap_or(120).clamp(1, 600));
    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if start.elapsed() >= timeout => {
                timed_out = true;
                let _ = child.kill();
                break child.wait().ok();
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => break None,
        }
    };
    let stdout = String::from_utf8_lossy(&out_thread.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&err_thread.join().unwrap_or_default()).into_owned();
    let (stdout, cut_out) = truncate(&scrub(&stdout, &secrets));
    let (stderr, cut_err) = truncate(&scrub(&stderr, &secrets));
    let exit_code = status.and_then(|s| s.code());
    ToolResult {
        text: json!({
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "truncated": cut_out || cut_err,
            "timed_out": timed_out,
        })
        .to_string(),
        is_error: timed_out || exit_code != Some(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Answers like the app would, without a vault.
    struct Fake {
        may_run: bool,
        calls: Vec<(String, Value)>,
    }

    impl Backend for Fake {
        fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
            self.calls.push((method.to_string(), params.clone()));
            match method {
                "search" => Ok(json!({ "items": [{ "id": "i1", "title": "GitHub" }] })),
                "read" => Err("the user did not allow this".to_string()),
                "read_many" => {
                    let refs = params["refs"].as_array().cloned().unwrap_or_default();
                    let values: serde_json::Map<String, Value> =
                        refs.iter().map(|r| (r.as_str().unwrap().to_string(), json!("hunter2"))).collect();
                    Ok(json!({ "values": values }))
                }
                "generate" => Ok(json!({ "value": "xyz", "entropy_bits": 10 })),
                other => Err(format!("unexpected {other}")),
            }
        }
        fn status(&mut self) -> Value {
            json!({ "mode": "fake" })
        }
        fn may_run(&self) -> bool {
            self.may_run
        }
    }

    #[test]
    fn definitions_are_valid_schemas() {
        let tools = definitions();
        assert_eq!(tools.len(), 9);
        for t in &tools {
            assert!(t["name"].is_string());
            assert!(t["description"].as_str().unwrap().len() > 20);
            assert_eq!(t["inputSchema"]["type"], "object");
            assert_eq!(t["inputSchema"]["additionalProperties"], false);
            assert!(t["annotations"]["readOnlyHint"].is_boolean());
        }
    }

    #[test]
    fn tools_forward_and_report_errors() {
        let mut fake = Fake { may_run: true, calls: Vec::new() };
        let out = call_tool(&mut fake, "search_items", json!({ "query": "git" }));
        assert!(!out.is_error && out.text.contains("GitHub"));
        assert_eq!(fake.calls[0].0, "search");
        let out = call_tool(&mut fake, "read_field", json!({ "item": "GitHub", "field": "password" }));
        assert!(out.is_error && out.text.contains("did not allow"));
        let out = call_tool(&mut fake, "save_login", json!({ "title": "x", "generate_password": true }));
        assert!(out.is_error, "the fake has no create_item");
        assert_eq!(fake.calls.last().unwrap().1["generate"], true);
        assert!(call_tool(&mut fake, "nope", json!({})).is_error);
        assert!(call_tool(&mut fake, "search_items", json!([1])).is_error);
        assert!(call_tool(&mut fake, "agent_status", Value::Null).text.contains("fake"));
    }

    #[cfg(unix)]
    #[test]
    fn run_command_scrubs_secrets() {
        let mut fake = Fake { may_run: true, calls: Vec::new() };
        let out = call_tool(
            &mut fake,
            "run_command",
            json!({ "command": ["sh", "-c", "echo \"pw=$X url=p%3Ahunter2\"; echo plain=$Y >&2"],
                "env": { "X": "2s://Personal/Db/password", "Y": "literal" } }),
        );
        assert!(!out.is_error, "{}", out.text);
        let v: Value = serde_json::from_str(&out.text).unwrap();
        assert_eq!(v["exit_code"], 0);
        assert!(!out.text.contains("hunter2"), "{}", out.text);
        assert!(v["stdout"].as_str().unwrap().contains("pw=«2s://Personal/Db/password»"));
        assert!(v["stdout"].as_str().unwrap().contains("url=p%3A«2s://Personal/Db/password»"));
        assert!(v["stderr"].as_str().unwrap().contains("plain=literal"));
        let (method, params) = &fake.calls[0];
        assert_eq!(method, "read_many");
        assert_eq!(params["refs"], json!(["2s://Personal/Db/password"]));
        assert!(params["reason"].as_str().unwrap().starts_with("run sh -c"));

        let out = call_tool(&mut fake, "run_command", json!({ "command": ["sh", "-c", "exit 3"] }));
        assert!(out.is_error);
        assert!(out.text.contains("\"exit_code\":3"));

        let out = call_tool(&mut fake, "run_command", json!({ "command": ["sleep", "5"], "timeout_secs": 1 }));
        assert!(out.is_error && out.text.contains("\"timed_out\":true"));

        let mut off = Fake { may_run: false, calls: Vec::new() };
        assert!(call_tool(&mut off, "run_command", json!({ "command": ["true"] })).text.contains("turned off"));
        assert!(call_tool(&mut fake, "run_command", json!({ "command": [] })).is_error);
        assert!(call_tool(&mut fake, "run_command", json!({ "command": ["/nonexistent/x"] }))
            .text
            .contains("could not run"));
    }
}
