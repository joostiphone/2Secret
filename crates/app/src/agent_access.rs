//! Desktop: Agent Access (*Settings → Desktop app → AI agents*). AI tools
//! (Claude Code, Claude Desktop, Cursor, Codex, any MCP client) reach the
//! vault through `2secret mcp`, which talks to this app over a local
//! socket. Every secret needs the user's consent here (once, for these items
//! until 2Secret locks, or for a few hours); searching titles and websites
//! needs none once the agent is allowed to connect. Everything an agent did
//! is logged; agents and their permissions are in the settings.
//!
//! The listener and its connections run on their own threads, like the SSH
//! agent's: they check the agent's key (`twosecret_core::agent`), identify
//! the program on the other end, and hand every request to the UI, which
//! holds the vault and asks the user. The listener is `access.sock` in the
//! data directory (a named pipe per user on Windows).

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;

use dioxus::prelude::*;
use serde_json::{json, Value};
use tokio::sync::Notify;
use twosecret_core::agent::{
    self, ActionKind, AgentError, AgentIdentity, AgentStore, Ask, AuthParams, AuthResult, Decision, HelloParams,
    HelloResult, Outcome, Request, UntilLock, GRANT_HOURS, MAX_LINE, PROTOCOL,
};
use twosecret_core::crypto::EncString;
use twosecret_core::util::{now, unb64};

use crate::biometric;
use crate::components::shell::relative_time;
use crate::i18n::t;
use crate::icons::{either, Icon};
use crate::platform;
use crate::state::*;

/// How long a client waits for an unlock or the user's answer.
const WAIT: Duration = Duration::from_secs(120);

/// Requests for the UI thread.
static REQUESTS: Mutex<Vec<AccessRequest>> = Mutex::new(Vec::new());
static REQUEST: Notify = Notify::const_new();
/// Requests whose client stopped waiting.
static CANCELLED: Mutex<Vec<u64>> = Mutex::new(Vec::new());
/// A client waits for the vault to be unlocked.
static UNLOCK: Notify = Notify::const_new();
/// Whether the vault is unlocked, for the socket threads.
static UNLOCKED: AtomicBool = AtomicBool::new(false);
/// Bumped to stop the running listener.
static GENERATION: AtomicU64 = AtomicU64::new(0);
static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

enum Kind {
    /// `auth` succeeded: may the agent connect?
    Connect(AgentIdentity),
    Call {
        agent: AgentIdentity,
        request: Box<Request>,
    },
}

struct AccessRequest {
    id: u64,
    kind: Kind,
    reply: mpsc::Sender<Result<Value, AgentError>>,
}

#[derive(Clone, PartialEq)]
pub enum Status {
    Off,
    Listening,
    /// Another 2Secret listens for this data directory.
    InUse,
    Failed(String),
}

pub static STATUS: GlobalSignal<Status> = Signal::global(|| Status::Off);
/// Requests that wait for the user, oldest first.
static PROMPTS: GlobalSignal<Vec<Prompt>> = Signal::global(Vec::new);
/// The agents, their permissions and the log, while the vault is unlocked.
pub static STORE: GlobalSignal<Option<AgentStore>> = Signal::global(|| None);

#[derive(Clone)]
struct Prompt {
    id: u64,
    identity: AgentIdentity,
    ask: Ask,
    request: std::rc::Rc<std::cell::RefCell<Option<AccessRequest>>>,
}

thread_local! {
    /// "For these items until 2Secret locks".
    static UNTIL_LOCK: std::cell::RefCell<UntilLock> = std::cell::RefCell::new(UntilLock::default());
}

// ---------------------------------------------------------------------------
// Socket threads
// ---------------------------------------------------------------------------

/// What the operating system says about the program on the other end.
#[derive(Clone, Debug, Default)]
pub struct Peer {
    pub exe: Option<String>,
    pub parent: Option<String>,
}

fn wait_unlocked() -> bool {
    if UNLOCKED.load(Ordering::SeqCst) {
        return true;
    }
    UNLOCK.notify_one();
    let deadline = std::time::Instant::now() + WAIT;
    while std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        if UNLOCKED.load(Ordering::SeqCst) {
            return true;
        }
    }
    false
}

/// Hand a request to the UI and wait for the answer.
fn ask_ui(kind: Kind, generation: u64) -> Result<Value, AgentError> {
    if GENERATION.load(Ordering::SeqCst) != generation {
        return Err(AgentError::off());
    }
    if !wait_unlocked() {
        return Err(AgentError::locked());
    }
    let id = NEXT_REQUEST.fetch_add(1, Ordering::SeqCst);
    let (reply, answer) = mpsc::channel();
    REQUESTS.lock().unwrap_or_else(|e| e.into_inner()).push(AccessRequest { id, kind, reply });
    REQUEST.notify_one();
    match answer.recv_timeout(WAIT) {
        Ok(result) => result,
        Err(_) => {
            CANCELLED.lock().unwrap_or_else(|e| e.into_inner()).push(id);
            REQUEST.notify_one();
            Err(AgentError::timeout())
        }
    }
}

/// One line, at most [`MAX_LINE`] bytes; `Ok(false)` at the end of the stream.
fn read_line<R: Read>(reader: &mut BufReader<R>, out: &mut Vec<u8>) -> std::io::Result<bool> {
    out.clear();
    loop {
        let (used, done) = {
            let buf = reader.fill_buf()?;
            if buf.is_empty() {
                return Ok(!out.is_empty());
            }
            match buf.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    out.extend_from_slice(&buf[..i]);
                    (i + 1, true)
                }
                None => {
                    out.extend_from_slice(buf);
                    (buf.len(), false)
                }
            }
        };
        reader.consume(used);
        if out.len() > MAX_LINE {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "line too long"));
        }
        if done {
            return Ok(true);
        }
    }
}

/// The id, method and params of a JSON-RPC request line.
fn envelope(line: &[u8]) -> Result<(Value, String, Option<Value>), AgentError> {
    let value: Value = serde_json::from_slice(line).map_err(|e| AgentError::invalid(format!("not JSON-RPC: {e}")))?;
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let method = value.get("method").and_then(Value::as_str).ok_or_else(|| AgentError::invalid("method missing"))?;
    Ok((id, method.to_string(), value.get("params").cloned()))
}

fn write_reply(writer: &mut impl Write, id: &Value, result: Result<Value, AgentError>) -> std::io::Result<()> {
    let reply = match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(e) => json!({ "jsonrpc": "2.0", "id": id, "error": e }),
    };
    let mut text = reply.to_string();
    text.push('\n');
    writer.write_all(text.as_bytes())?;
    writer.flush()
}

/// The next line, which has to be the request `wanted` (`hello`, `auth`).
fn expect<R: Read, W: Write>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    line: &mut Vec<u8>,
    wanted: &str,
) -> Option<(Value, Value)> {
    if !read_line(reader, line).ok()? {
        return None;
    }
    let (id, method, params) = match envelope(line) {
        Ok(v) => v,
        Err(e) => {
            let _ = write_reply(writer, &Value::Null, Err(e));
            return None;
        }
    };
    if method != wanted {
        let _ = write_reply(writer, &id, Err(AgentError::not_paired()));
        return None;
    }
    Some((id, params.unwrap_or(Value::Null)))
}

/// One client connection (its own thread): `hello`, `auth`, then requests.
fn serve(reader: impl Read, mut writer: impl Write, peer: Peer, generation: u64) {
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    // 1. hello: the agent announces itself and its key.
    let Some((id, params)) = expect(&mut reader, &mut writer, &mut line, "hello") else { return };
    let hello: HelloParams = match serde_json::from_value(params) {
        Ok(h) => h,
        Err(e) => {
            let _ = write_reply(&mut writer, &id, Err(AgentError::invalid(e.to_string())));
            return;
        }
    };
    if hello.protocol != PROTOCOL {
        let message = format!("2Secret speaks agent protocol {PROTOCOL}, the agent protocol {}", hello.protocol);
        let _ = write_reply(&mut writer, &id, Err(AgentError::invalid(message)));
        return;
    }
    let nonce = agent::new_nonce();
    let answer =
        HelloResult { protocol: PROTOCOL, app_version: env!("CARGO_PKG_VERSION").to_string(), nonce: nonce.clone() };
    if write_reply(&mut writer, &id, serde_json::to_value(answer).map_err(|e| AgentError::invalid(e.to_string())))
        .is_err()
    {
        return;
    }
    // 2. auth: the signature proves the key.
    let Some((id, params)) = expect(&mut reader, &mut writer, &mut line, "auth") else { return };
    let auth: AuthParams = match serde_json::from_value(params) {
        Ok(a) => a,
        Err(e) => {
            let _ = write_reply(&mut writer, &id, Err(AgentError::invalid(e.to_string())));
            return;
        }
    };
    let nonce_bytes = unb64(&nonce).unwrap_or_default();
    let agent_id = match agent::verify_hello(&hello.agent_key, &nonce_bytes, &auth.signature) {
        Ok(id) => id,
        Err(e) => {
            let _ = write_reply(&mut writer, &id, Err(AgentError::new(AgentError::DENIED, e.to_string())));
            return;
        }
    };
    let identity = AgentIdentity::new(&agent_id, &hello, peer.exe, peer.parent);
    // 3. The user allows the agent (the first time).
    let result = ask_ui(Kind::Connect(identity.clone()), generation);
    let connected = result.is_ok();
    if write_reply(&mut writer, &id, result).is_err() || !connected {
        return;
    }
    // 4. Requests, one at a time.
    while let Ok(true) = read_line(&mut reader, &mut line) {
        let (id, method, params) = match envelope(&line) {
            Ok(v) => v,
            Err(e) => {
                let _ = write_reply(&mut writer, &Value::Null, Err(e));
                continue;
            }
        };
        let result = match Request::parse(&method, params) {
            Err(e) => Err(e),
            Ok(Request::Ping) => Ok(json!({})),
            Ok(Request::Generate(p)) => {
                let opts = p.options();
                Ok(json!({ "value": opts.generate(), "entropy_bits": opts.entropy_bits().round() }))
            }
            Ok(request) => ask_ui(Kind::Call { agent: identity.clone(), request: Box::new(request) }, generation),
        };
        if write_reply(&mut writer, &id, result).is_err() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// In the app
// ---------------------------------------------------------------------------

/// In the app component: the listener, the store and the user's consent.
pub fn use_agent_access() {
    use_hook(|| {
        spawn(async {
            loop {
                UNLOCK.notified().await;
                if *PHASE.peek() != Phase::Unlocked {
                    crate::tray::show();
                }
            }
        });
        spawn(async {
            loop {
                REQUEST.notified().await;
                let cancelled = std::mem::take(&mut *CANCELLED.lock().unwrap_or_else(|e| e.into_inner()));
                for id in cancelled {
                    cancel(id);
                }
                let requests = std::mem::take(&mut *REQUESTS.lock().unwrap_or_else(|e| e.into_inner()));
                for request in requests {
                    handle(request);
                }
            }
        });
    });
    // Start or stop with the setting (once the preferences are read).
    use_effect(|| {
        let phase = PHASE.read().clone();
        let on = PREFS.read().agent_access;
        if phase == Phase::Loading {
            return;
        }
        let status = STATUS.peek().clone();
        if on && status == Status::Off {
            *STATUS.write() = match os::start() {
                Ok(()) => Status::Listening,
                Err(None) => Status::InUse,
                Err(Some(e)) => Status::Failed(e),
            };
        } else if !on && status != Status::Off {
            if status == Status::Listening {
                os::stop();
            }
            *STATUS.write() = Status::Off;
        }
    });
    // The store while unlocked; nothing is allowed after locking.
    use_effect(|| {
        let unlocked = *PHASE.read() == Phase::Unlocked && PREFS.read().agent_access;
        UNLOCKED.store(unlocked, Ordering::SeqCst);
        if unlocked {
            if STORE.peek().is_none() {
                *STORE.write() = Some(load_store());
            }
        } else {
            UNTIL_LOCK.with_borrow_mut(UntilLock::clear);
            if STORE.peek().is_some() {
                *STORE.write() = None;
            }
            if !PROMPTS.peek().is_empty() {
                // Dropping the requests refuses them.
                PROMPTS.write().clear();
            }
        }
    });
}

fn load_store() -> AgentStore {
    let session = SESSION.peek();
    let Some(session) = session.as_ref() else { return AgentStore::default() };
    let Ok(Some(json)) = platform::storage().read(&active_key(AGENTS_KEY)) else { return AgentStore::default() };
    EncString::parse(&json)
        .and_then(|enc| AgentStore::open(&enc, session.account_key(), &session.account().id))
        .unwrap_or_default()
}

fn save_store() {
    let session = SESSION.peek();
    let Some(session) = session.as_ref() else { return };
    let store = STORE.peek();
    let Some(store) = store.as_ref() else { return };
    if let Ok(enc) = store.seal(session.account_key(), &session.account().id) {
        let _ = platform::storage().write(&active_key(AGENTS_KEY), enc.as_str());
    }
}

fn auth_result(identity: &AgentIdentity) -> Value {
    serde_json::to_value(AuthResult { agent_id: identity.id.clone(), state: "paired".into() }).unwrap_or(Value::Null)
}

/// Run a request against the vault (consent was given or not needed).
fn run(request: &Request) -> Result<Value, AgentError> {
    touch();
    if request.writes() {
        let result = {
            let mut guard = SESSION.write();
            let session = guard.as_mut().ok_or_else(AgentError::locked)?;
            agent::execute_mut(session, request)
        };
        if result.is_ok() {
            persist();
            request_sync();
        }
        result
    } else {
        let guard = SESSION.peek();
        let session = guard.as_ref().ok_or_else(AgentError::locked)?;
        agent::execute(session, request)
    }
}

/// A new request from a socket thread: answer it, or ask the user.
fn handle(request: AccessRequest) {
    if *PHASE.peek() != Phase::Unlocked || STORE.peek().is_none() {
        let _ = request.reply.send(Err(AgentError::locked()));
        return;
    }
    let ts = now();
    match &request.kind {
        Kind::Connect(identity) => {
            let paired = STORE.peek().as_ref().is_some_and(|s| s.is_paired(identity));
            if paired {
                if let Some(store) = STORE.write().as_mut() {
                    store.pair(identity, ts);
                }
                save_store();
                let _ = request.reply.send(Ok(auth_result(identity)));
            } else {
                prompt(identity.clone(), Ask::connect(), request);
            }
        }
        Kind::Call { agent, request: req } => {
            if !STORE.peek().as_ref().is_some_and(|s| s.is_paired(agent)) {
                let _ = request.reply.send(Err(AgentError::not_paired()));
                return;
            }
            let ask = {
                let guard = SESSION.peek();
                match guard.as_ref() {
                    Some(session) => agent::ask_for(session, req),
                    None => Err(AgentError::locked()),
                }
            };
            match ask {
                Err(e) => {
                    let _ = request.reply.send(Err(e));
                }
                Ok(None) => {
                    if let Some(store) = STORE.write().as_mut() {
                        store.touch(&agent.id, ts);
                    }
                    let _ = request.reply.send(run(req));
                }
                Ok(Some(ask)) => {
                    let covered = UNTIL_LOCK.with_borrow(|u| u.covers(&agent.id, &ask))
                        || STORE.peek().as_ref().is_some_and(|s| s.covers(&agent.id, &ask, ts));
                    if covered {
                        if let Some(store) = STORE.write().as_mut() {
                            store.record(agent, &ask, Outcome::Granted, ts);
                            store.touch(&agent.id, ts);
                        }
                        save_store();
                        let _ = request.reply.send(run(req));
                    } else {
                        prompt(agent.clone(), ask, request);
                    }
                }
            }
        }
    }
}

fn prompt(identity: AgentIdentity, ask: Ask, request: AccessRequest) {
    PROMPTS.write().push(Prompt {
        id: request.id,
        identity,
        ask,
        request: std::rc::Rc::new(std::cell::RefCell::new(Some(request))),
    });
    crate::tray::show();
}

/// The client stopped waiting: the question goes, the log says so.
fn cancel(id: u64) {
    let prompt = {
        let mut prompts = PROMPTS.write();
        let Some(at) = prompts.iter().position(|p| p.id == id) else { return };
        prompts.remove(at)
    };
    if let Some(store) = STORE.write().as_mut() {
        store.record(&prompt.identity, &prompt.ask, Outcome::Timeout, now());
    }
    save_store();
}

/// The user answered.
fn decide(prompt: Prompt, decision: Decision) {
    {
        let mut prompts = PROMPTS.write();
        if let Some(at) = prompts.iter().position(|p| p.id == prompt.id) {
            prompts.remove(at);
        }
    }
    let Some(request) = prompt.request.borrow_mut().take() else { return };
    if decision == Decision::Deny {
        if let Some(store) = STORE.write().as_mut() {
            store.record(&prompt.identity, &prompt.ask, Outcome::Denied, now());
        }
        save_store();
        let _ = request.reply.send(Err(AgentError::denied()));
        return;
    }
    let gate = PREFS.peek().agent_biometric && biometric::available().is_some();
    match (gate, biometric_unlock()) {
        (true, Some(config)) => {
            let identity = prompt.identity.clone();
            let ask = prompt.ask.clone();
            spawn(async move {
                let reason = t("agent.biometric_reason").replace("{agent}", &identity.name);
                let account_id = config.account_id.clone();
                let checked = platform::run_heavy(move || biometric::device_key(&account_id, &reason)).await;
                match checked {
                    Ok(_) => finish(identity, ask, request, decision),
                    Err(e) => {
                        if let biometric::Error::Failed(msg) = &e {
                            toast_err(msg);
                        }
                        if let Some(store) = STORE.write().as_mut() {
                            store.record(&identity, &ask, Outcome::Denied, now());
                        }
                        save_store();
                        let _ = request.reply.send(Err(AgentError::denied()));
                    }
                }
            });
        }
        _ => finish(prompt.identity, prompt.ask, request, decision),
    }
}

fn finish(identity: AgentIdentity, ask: Ask, request: AccessRequest, decision: Decision) {
    let ts = now();
    touch();
    match decision {
        Decision::UntilLock => UNTIL_LOCK.with_borrow_mut(|u| u.allow(&identity.id, &ask)),
        Decision::ForHours => {
            if let Some(store) = STORE.write().as_mut() {
                store.grant(&identity.id, &ask, ts);
            }
        }
        Decision::Once | Decision::Deny => {}
    }
    if let Some(store) = STORE.write().as_mut() {
        if ask.action == ActionKind::Connect {
            store.pair(&identity, ts);
        }
        store.record(&identity, &ask, Outcome::Allowed, ts);
        store.touch(&identity.id, ts);
    }
    save_store();
    let result = match &request.kind {
        Kind::Connect(_) => Ok(auth_result(&identity)),
        Kind::Call { request, .. } => run(request),
    };
    let _ = request.reply.send(result);
}

/// Forget an agent: it has to be allowed again to connect.
pub fn revoke(agent_id: &str) {
    if let Some(store) = STORE.write().as_mut() {
        store.revoke_agent(agent_id);
    }
    UNTIL_LOCK.with_borrow_mut(UntilLock::clear);
    save_store();
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

fn join(words: &[String]) -> String {
    words.join(", ")
}

/// The question to the user, above everything else.
#[component]
pub fn AgentPrompt() -> Element {
    let mut scope = use_signal(|| Decision::Once);
    // The SSH agent's question goes first; two at once would overlap.
    if crate::ssh_agent::has_prompt() {
        return rsx! {};
    }
    let prompts = PROMPTS.read();
    let Some(prompt) = prompts.first().cloned() else { return rsx! {} };
    drop(prompts);
    let who = prompt.identity.display();
    let ask = prompt.ask.clone();
    let title = match ask.action {
        ActionKind::Connect => t("agent.title_connect"),
        _ => t("agent.title"),
    };
    let text = match (ask.action, ask.targets.as_slice()) {
        (ActionKind::Connect, _) => t("agent.connect_ask").replace("{agent}", &who),
        (ActionKind::Read, [one]) => t("agent.read_ask")
            .replace("{agent}", &who)
            .replace("{fields}", &join(&one.fields))
            .replace("{item}", &one.title),
        (ActionKind::Read, _) => t("agent.read_many_ask").replace("{agent}", &who),
        (ActionKind::Otp, targets) => t("agent.otp_ask")
            .replace("{agent}", &who)
            .replace("{item}", &targets.first().map(|t| t.title.clone()).unwrap_or_default()),
        (ActionKind::Create, _) => t("agent.create_ask")
            .replace("{agent}", &who)
            .replace("{detail}", ask.detail.as_deref().unwrap_or_default()),
        (ActionKind::Update | ActionKind::Fill, targets) => {
            let target = targets.first();
            t("agent.update_ask")
                .replace("{agent}", &who)
                .replace("{fields}", &target.map(|t| join(&t.fields)).unwrap_or_default())
                .replace("{item}", &target.map(|t| t.title.clone()).unwrap_or_default())
        }
    };
    let many = ask.action == ActionKind::Read && ask.targets.len() > 1;
    let grantable = ask.action.grantable();
    let id = prompt.id;
    // Captures only the id and the signal, so it can be used in every handler.
    let mut answer = move |decision: Decision| {
        let found = PROMPTS.peek().iter().find(|p| p.id == id).cloned();
        if let Some(found) = found {
            decide(found, decision);
        }
        scope.set(Decision::Once);
    };
    rsx! {
        div { class: "modal-backdrop",
            onkeydown: move |e: KeyboardEvent| {
                if e.key() == Key::Escape {
                    answer(Decision::Deny);
                }
            },
            div { class: "modal",
                div { class: "modal-head",
                    h3 { {title} }
                    Icon { name: "terminal", size: 18 }
                }
                div { class: "modal-body col",
                    p { "{text}" }
                    if many {
                        ul {
                            for target in ask.targets.iter() {
                                li { key: "{target.item_id}", "{target.title}: {join(&target.fields)}" }
                            }
                        }
                    }
                    if let Some(reason) = ask.reason.as_deref() {
                        p { class: "small", {t("agent.reason").replace("{reason}", reason)} }
                    }
                    match (&prompt.identity.exe, &prompt.identity.parent) {
                        (Some(exe), Some(parent)) => rsx! {
                            div { class: "small muted mono", {t("agent.program").replace("{path}", exe)} }
                            div { class: "small muted mono", {t("agent.started_by").replace("{path}", parent)} }
                        },
                        (Some(exe), None) => rsx! { div { class: "small muted mono", {t("agent.program").replace("{path}", exe)} } },
                        _ => rsx! { div { class: "small muted", {t("agent.unverified")} } },
                    }
                    if grantable {
                        label { class: "checkbox",
                            input { r#type: "radio", name: "agent-scope", checked: scope() == Decision::Once,
                                onchange: move |_| scope.set(Decision::Once) }
                            {t("agent.allow_once")}
                        }
                        label { class: "checkbox",
                            input { r#type: "radio", name: "agent-scope", checked: scope() == Decision::UntilLock,
                                onchange: move |_| scope.set(Decision::UntilLock) }
                            {t("agent.allow_until_lock")}
                        }
                        label { class: "checkbox",
                            input { r#type: "radio", name: "agent-scope", checked: scope() == Decision::ForHours,
                                onchange: move |_| scope.set(Decision::ForHours) }
                            {t("agent.allow_hours").replace("{hours}", &GRANT_HOURS.to_string())}
                        }
                    }
                }
                div { class: "modal-foot",
                    // The keyboard comes here: Enter refuses, allowing takes a click.
                    button { class: "btn",
                        onmounted: move |e: MountedEvent| async move {
                            let _ = e.set_focus(true).await;
                        },
                        onclick: move |_| answer(Decision::Deny),
                        {t("agent.deny")}
                    }
                    button { class: "btn primary",
                        onclick: move |_| answer(if grantable { scope() } else { Decision::Once }),
                        {t("agent.allow")}
                    }
                }
            }
        }
    }
}

/// The MCP configuration to paste into an AI tool.
pub fn mcp_config() -> String {
    "{\n  \"mcpServers\": {\n    \"2secret\": { \"command\": \"2secret\", \"args\": [\"mcp\"] }\n  }\n}".to_string()
}

/// *Settings → Desktop app*.
#[component]
pub fn AgentAccessRow() -> Element {
    let on = PREFS.read().agent_access;
    let status = STATUS.read().clone();
    let kind = use_hook(biometric::available);
    let gate_possible = kind.is_some() && biometric_unlock().is_some();
    let gate = PREFS.read().agent_biometric;
    let store = STORE.read();
    let agents: Vec<_> = store.as_ref().map(|s| s.agents.clone()).unwrap_or_default();
    let ts = now();
    let grants = |id: &str| store.as_ref().map(|s| s.grants_of(id, ts).len()).unwrap_or(0);
    let log: Vec<_> = store.as_ref().map(|s| s.log.iter().rev().take(50).cloned().collect()).unwrap_or_default();
    let agent_rows = agents
        .iter()
        .map(|a| (a.id.clone(), a.id.clone(), a.name.clone(), a.exe.clone(), a.last_seen, grants(&a.id)))
        .collect::<Vec<_>>();
    drop(store);
    rsx! {
        div { class: "settings-row",
            div { class: "k",
                div { class: "t", {t("agent.row")} }
                div { class: "d", {t("agent.row_desc")} }
                match status {
                    Status::Listening => rsx! {
                        div { class: "d", {t("agent.setup")} }
                        pre { class: "code-block", "{mcp_config()}" }
                    },
                    Status::InUse => rsx! { div { class: "d warn-text", {t("agent.in_use")} } },
                    Status::Failed(e) => rsx! { div { class: "d danger-text", {t("agent.failed").replace("{error}", &e)} } },
                    Status::Off => rsx! {},
                }
                if on && gate_possible {
                    label { class: "checkbox", style: "margin-top:8px",
                        input { r#type: "checkbox", checked: gate,
                            onchange: move |e| {
                                PREFS.write().agent_biometric = e.checked();
                                save_prefs();
                            }
                        }
                        {with_kind(t("agent.biometric"), kind.unwrap_or(biometric::Kind::TouchId))}
                    }
                }
                if on {
                    div { class: "d", style: "margin-top:8px;font-weight:600", {t("agent.agents")} }
                    if agent_rows.is_empty() {
                        div { class: "d", {t("agent.none")} }
                    }
                    for (id, revoke_id, name, exe, last_seen, count) in agent_rows.iter().cloned() {
                        div { class: "row", key: "{id}", style: "align-items:center;gap:8px;margin-top:4px",
                            div { class: "grow",
                                div { "{name} " span { class: "small muted mono", "{id}" } }
                                if let Some(exe) = exe {
                                    div { class: "small muted mono", "{exe}" }
                                }
                                div { class: "small muted",
                                    {t("agent.last_used").replace("{time}", &relative_time(last_seen))}
                                    if count > 0 {
                                        " · " {t("agent.grants").replace("{count}", &count.to_string())}
                                    }
                                }
                            }
                            button { class: "btn small", onclick: move |_| revoke(&revoke_id), {t("agent.revoke")} }
                        }
                    }
                    if !log.is_empty() {
                        div { class: "row", style: "align-items:center;margin-top:8px",
                            div { class: "d grow", style: "font-weight:600", {t("agent.log")} }
                            button { class: "btn small",
                                onclick: move |_| {
                                    if let Some(store) = STORE.write().as_mut() {
                                        store.clear_log();
                                    }
                                    save_store();
                                },
                                {t("agent.clear_log")}
                            }
                        }
                        for (i, entry) in log.iter().enumerate() {
                            div { class: "small muted", key: "{i}",
                                "{relative_time(entry.ts)} · {entry.agent} · "
                                {t(&format!("agent.action.{}", entry.action.id()))}
                                if !entry.items.is_empty() {
                                    " · {join(&entry.items)}"
                                }
                                " · " {t(&format!("agent.outcome.{}", outcome_id(entry.outcome)))}
                            }
                        }
                    }
                }
            }
            button { class: either(on, "btn small", "btn small primary"),
                onclick: move |_| {
                    PREFS.write().agent_access = !on;
                    save_prefs();
                },
                {either(on, t("common.turn_off"), t("common.turn_on"))}
            }
        }
    }
}

fn outcome_id(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Allowed => "allowed",
        Outcome::Granted => "granted",
        Outcome::Denied => "denied",
        Outcome::Timeout => "timeout",
    }
}

// ---------------------------------------------------------------------------
// The listener per operating system
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod os {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;

    use super::{Peer, GENERATION};

    pub const SOCKET: &str = "access.sock";

    fn socket() -> PathBuf {
        crate::platform::data_dir().join(SOCKET)
    }

    /// `Err(None)`: another 2Secret listens there.
    pub fn start() -> Result<(), Option<String>> {
        // Creates the data directory, only for this user.
        let _ = crate::platform::storage();
        let path = socket();
        if path.exists() {
            if UnixStream::connect(&path).is_ok() {
                return Err(None);
            }
            let _ = std::fs::remove_file(&path);
        }
        let listener = UnixListener::bind(&path).map_err(|e| Some(e.to_string()))?;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        let generation = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if GENERATION.load(Ordering::SeqCst) != generation {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let peer = peer(&stream);
                let Ok(writer) = stream.try_clone() else { continue };
                std::thread::spawn(move || super::serve(stream, writer, peer, generation));
            }
        });
        Ok(())
    }

    pub fn stop() {
        GENERATION.fetch_add(1, Ordering::SeqCst);
        let path = socket();
        // Wakes the listener, which then sees it is stopped.
        let _ = UnixStream::connect(&path);
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(target_os = "linux")]
    fn peer(stream: &UnixStream) -> Peer {
        use std::os::fd::AsRawFd;
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ok = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        } == 0;
        if !ok || credentials.pid <= 0 {
            return Peer::default();
        }
        let exe = |pid: i32| {
            std::fs::read_link(format!("/proc/{pid}/exe"))
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
                .or_else(|| std::fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|n| n.trim().to_string()))
        };
        let parent = std::fs::read_to_string(format!("/proc/{}/stat", credentials.pid))
            .ok()
            .and_then(|stat| stat.rsplit_once(')')?.1.split_whitespace().nth(1)?.parse::<i32>().ok())
            .filter(|ppid| *ppid > 1)
            .and_then(exe);
        Peer { exe: exe(credentials.pid), parent }
    }

    #[cfg(target_os = "macos")]
    fn peer(stream: &UnixStream) -> Peer {
        use std::os::fd::AsRawFd;
        let mut pid: libc::pid_t = 0;
        let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        let ok = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::pid_t).cast(),
                &mut length,
            )
        } == 0;
        if !ok || pid <= 0 {
            return Peer::default();
        }
        let path = |pid: libc::pid_t| {
            let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
            let n = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
            (n > 0).then(|| String::from_utf8_lossy(&path[..n as usize]).into_owned())
        };
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let got = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&mut info as *mut libc::proc_bsdinfo).cast(), size)
        };
        let parent = (got == size && info.pbi_ppid > 1).then(|| path(info.pbi_ppid as libc::pid_t)).flatten();
        Peer { exe: path(pid), parent }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn peer(_stream: &UnixStream) -> Peer {
        Peer::default()
    }
}

#[cfg(windows)]
mod os {
    use std::os::windows::io::FromRawHandle;
    use std::sync::atomic::Ordering;

    use windows::core::{HSTRING, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, HANDLE};
    use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::{Peer, GENERATION};

    /// One pipe per data directory, so per user (like the link pipe).
    fn pipe() -> String {
        format!(r"\\.\pipe\2Secret agent {}", crate::platform::data_dir().to_string_lossy().replace('\\', "/"))
    }

    fn create(first: bool) -> Option<HANDLE> {
        let flags = if first { PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE } else { PIPE_ACCESS_DUPLEX };
        let pipe = unsafe {
            CreateNamedPipeW(
                &HSTRING::from(pipe()),
                flags,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                64 * 1024,
                64 * 1024,
                0,
                None,
            )
        };
        (!pipe.is_invalid()).then_some(pipe)
    }

    /// `Err(None)`: another 2Secret has the pipe.
    pub fn start() -> Result<(), Option<String>> {
        let first = create(true).ok_or(None)?;
        let generation = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        // A handle is a pointer, which threads may not share.
        let raw = first.0 as usize;
        std::thread::spawn(move || {
            let mut pipe = HANDLE(raw as *mut _);
            loop {
                match unsafe { ConnectNamedPipe(pipe, None) } {
                    Ok(()) => {}
                    Err(e) if e.code() == ERROR_PIPE_CONNECTED.to_hresult() => {}
                    Err(_) => {
                        let _ = unsafe { CloseHandle(pipe) };
                        break;
                    }
                }
                if GENERATION.load(Ordering::SeqCst) != generation {
                    let _ = unsafe { CloseHandle(pipe) };
                    break;
                }
                let peer = peer(pipe);
                let connection = pipe.0 as usize;
                std::thread::spawn(move || {
                    // Closes the pipe instance when done.
                    let stream = unsafe { std::fs::File::from_raw_handle(connection as *mut _) };
                    if let Ok(writer) = stream.try_clone() {
                        super::serve(stream, writer, peer, generation);
                    }
                });
                match create(false) {
                    Some(next) => pipe = next,
                    None => break,
                }
            }
        });
        Ok(())
    }

    pub fn stop() {
        GENERATION.fetch_add(1, Ordering::SeqCst);
        // Wakes the listener, which then sees it is stopped.
        let _ = std::fs::OpenOptions::new().read(true).write(true).open(pipe());
    }

    fn image_path(pid: u32) -> Option<String> {
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let mut buffer = vec![0u16; 1024];
        let mut size = buffer.len() as u32;
        let named =
            unsafe { QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), &mut size) };
        let _ = unsafe { CloseHandle(process) };
        named.ok()?;
        Some(String::from_utf16_lossy(&buffer[..size as usize]))
    }

    fn parent_pid(pid: u32) -> Option<u32> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.ok()?;
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut parent = None;
        if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
            loop {
                if entry.th32ProcessID == pid {
                    parent = Some(entry.th32ParentProcessID);
                    break;
                }
                if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                    break;
                }
            }
        }
        let _ = unsafe { CloseHandle(snapshot) };
        parent.filter(|p| *p > 4)
    }

    fn peer(pipe: HANDLE) -> Peer {
        let mut pid = 0u32;
        if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) }.is_err() {
            return Peer::default();
        }
        Peer { exe: image_path(pid), parent: parent_pid(pid).and_then(image_path) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_read_whole_and_capped() {
        let data = b"{\"a\":1}\n{\"b\":2}";
        let mut reader = BufReader::new(&data[..]);
        let mut line = Vec::new();
        assert!(read_line(&mut reader, &mut line).unwrap());
        assert_eq!(line, b"{\"a\":1}");
        assert!(read_line(&mut reader, &mut line).unwrap());
        assert_eq!(line, b"{\"b\":2}");
        assert!(!read_line(&mut reader, &mut line).unwrap());
        let long = vec![b'x'; MAX_LINE + 2];
        let mut reader = BufReader::new(&long[..]);
        assert!(read_line(&mut reader, &mut line).is_err());
    }

    #[test]
    fn envelopes_are_parsed() {
        let (id, method, params) =
            envelope(br#"{"jsonrpc":"2.0","id":7,"method":"search","params":{"query":"x"}}"#).unwrap();
        assert_eq!(id, 7);
        assert_eq!(method, "search");
        assert_eq!(params.unwrap()["query"], "x");
        assert!(envelope(b"nope").is_err());
        assert!(envelope(br#"{"id":1}"#).is_err());
        let mut out = Vec::new();
        write_reply(&mut out, &json!(3), Err(AgentError::denied())).unwrap();
        let reply: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(reply["id"], 3);
        assert_eq!(reply["error"]["code"], AgentError::DENIED);
        assert!(mcp_config().contains("\"2secret\""));
    }
}
