//! Agents elsewhere (*Settings → Agents elsewhere*): AI agents on other
//! computers reach this app through the sync server, which relays sealed
//! envelopes it cannot read (`twosecret_core::agent_remote`). This module
//! pairs an agent (a code the person pastes where the agent runs), keeps
//! the list of confirmed agents, fetches their requests while the vault is
//! unlocked and hands them to the same question as a local agent's
//! (`agent_access::submit_remote`), on the desktop and on the phone. The
//! answer goes back encrypted with the key the agent put in its request.
//!
//! Every unlocked device of the account sees a request; the first answer
//! counts and the question closes on the others.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

use dioxus::core::spawn_forever;
use dioxus::prelude::*;
use serde_json::Value;
use twosecret_client::{client_for, Client};
use twosecret_core::agent::{clean_label, AgentError, AgentIdentity, Request, NAME_MAX};
use twosecret_core::agent_remote::{
    self, AgentRecordData, PairingCode, RemotePublicKeys, VerifiedKeys, MAX_WAIT_SECONDS,
};
use twosecret_core::api::{AgentDto, AgentRequestDto};
use twosecret_core::crypto::SymmetricKey;
use twosecret_core::session::Session;
use twosecret_core::util::now;

use crate::agent_access;
use crate::components::shell::relative_time;
use crate::components::widgets::ModalFrame;
use crate::i18n::t;
use crate::icons::Icon;
use crate::platform;
use crate::state::*;

/// An agent as the settings show it.
#[derive(Clone, PartialEq)]
pub struct RemoteAgent {
    pub id: String,
    pub name: String,
    pub fingerprint: String,
    /// The computer the agent runs on, as it said.
    pub device: Option<String>,
    /// Paired, but not confirmed yet (on the device that made the code).
    pub pending: bool,
    pub last_seen: Option<i64>,
    pub paired_at: Option<i64>,
    /// The pinned keys and the record of a confirmed agent.
    confirmed: Option<(VerifiedKeys, AgentRecordData)>,
}

/// The agents of this account, while unlocked and linked to a server.
pub static REMOTE: GlobalSignal<Vec<RemoteAgent>> = Signal::global(Vec::new);
/// Why the list could not be fetched (an older server), for the settings.
pub static REMOTE_ERROR: GlobalSignal<Option<String>> = Signal::global(|| None);
/// The list should be fetched again at the next round.
static REFRESH: AtomicBool = AtomicBool::new(true);

/// A pending agent that proved it holds the pairing code.
#[derive(Clone, PartialEq)]
pub struct Found {
    pub id: String,
    pub name: String,
    pub version: String,
    pub device: Option<String>,
    pub fingerprint: String,
    keys: RemotePublicKeys,
}

/// The pairing dialog's state.
#[derive(Clone)]
pub struct Pairing {
    /// None when no code could be made (the error says why).
    code: Option<PairingCode>,
    pub expires_at: i64,
    pub found: Option<Found>,
    pub error: Option<String>,
    pub busy: bool,
}

pub static PAIRING: GlobalSignal<Option<Pairing>> = Signal::global(|| None);

pub fn request_refresh() {
    REFRESH.store(true, Ordering::SeqCst);
}

/// For the question to the user: where the agent is and its fingerprint.
pub fn describe(agent_id: &str) -> String {
    let list = REMOTE.read();
    match list.iter().find(|a| a.id == agent_id) {
        Some(a) => {
            let device = a.device.clone().unwrap_or_else(|| t("remote.unknown_device").to_string());
            t("remote.identity").replace("{device}", &device).replace("{fp}", &a.fingerprint)
        }
        None => t("remote.identity_unknown").to_string(),
    }
}

/// In the app component: fetch requests while unlocked.
pub fn use_remote_agents() {
    use_hook(|| {
        spawn(poll_loop());
    });
    use_effect(|| {
        if *PHASE.read() != Phase::Unlocked {
            if !REMOTE.peek().is_empty() {
                REMOTE.write().clear();
            }
            request_refresh();
        }
    });
}

/// A client for the server of the open session, if it is linked.
fn client() -> Option<Client> {
    let guard = SESSION.peek();
    client_for(guard.as_ref()?).ok()
}

fn server_too_old(e: &twosecret_client::Error) -> bool {
    e.is_not_found() || e.status() == Some(405)
}

async fn poll_loop() {
    // Requests handed to the user: the server's request id and the id of
    // the question in `agent_access`.
    let mut in_flight: HashMap<String, u64> = HashMap::new();
    let mut listed_at = 0i64;
    loop {
        if *PHASE.peek() != Phase::Unlocked {
            in_flight.clear();
            platform::sleep_ms(1000).await;
            continue;
        }
        let Some(client) = client() else {
            platform::sleep_ms(5000).await;
            continue;
        };
        if REFRESH.swap(false, Ordering::SeqCst) || now() - listed_at > 60 {
            listed_at = now();
            refresh_list(&client).await;
        }
        let confirmed: Vec<RemoteAgent> = REMOTE.peek().iter().filter(|a| a.confirmed.is_some()).cloned().collect();
        if confirmed.is_empty() {
            platform::sleep_ms(15_000).await;
            continue;
        }
        match client.agent_requests(MAX_WAIT_SECONDS).await {
            Ok(requests) => {
                // A request that is no longer open was answered on another
                // device (or expired): its question goes here.
                in_flight.retain(|id, ui| {
                    let open = requests.iter().any(|r| &r.id == id);
                    if !open {
                        agent_access::dismiss(*ui);
                    }
                    open
                });
                let mut taken = 0;
                for request in requests {
                    if in_flight.contains_key(&request.id) {
                        continue;
                    }
                    match take_request(request, &confirmed) {
                        Some((id, ui)) => {
                            in_flight.insert(id, ui);
                            taken += 1;
                        }
                        // An agent confirmed since the list was fetched.
                        None => request_refresh(),
                    }
                }
                // The server answers at once while a question is open here;
                // a pause keeps that from becoming a tight loop.
                if taken == 0 {
                    platform::sleep_ms(2000).await;
                }
            }
            Err(e) if server_too_old(&e) => {
                *REMOTE_ERROR.write() = Some(t("remote.server_old").to_string());
                platform::sleep_ms(60_000).await;
            }
            Err(_) => platform::sleep_ms(5000).await,
        }
    }
}

/// Fetch the list; records that do not open or name other keys than the
/// server lists are left out (nothing is answered for them).
async fn refresh_list(client: &Client) {
    match client.agents().await {
        Ok(dtos) => {
            let list = {
                let guard = SESSION.peek();
                match guard.as_ref() {
                    Some(session) => dtos.into_iter().filter_map(|d| describe_dto(session, d)).collect(),
                    None => Vec::new(),
                }
            };
            if *REMOTE.peek() != list {
                *REMOTE.write() = list;
            }
            if REMOTE_ERROR.peek().is_some() {
                *REMOTE_ERROR.write() = None;
            }
        }
        Err(e) if server_too_old(&e) => *REMOTE_ERROR.write() = Some(t("remote.server_old").to_string()),
        Err(_) => {}
    }
}

fn describe_dto(session: &Session, dto: AgentDto) -> Option<RemoteAgent> {
    let fingerprint = dto.keys.fingerprint().ok()?;
    match dto.record {
        Some(enc) => {
            let account_id = &session.account().id;
            let record = AgentRecordData::open(&enc, session.account_key(), account_id, &dto.id, &dto.keys).ok()?;
            let keys = record.keys.verify().ok()?;
            Some(RemoteAgent {
                id: dto.id,
                name: clean_label(&record.name, NAME_MAX),
                fingerprint: record.fingerprint.clone(),
                device: record.device.clone(),
                pending: false,
                last_seen: dto.last_seen_at,
                paired_at: Some(record.paired_at),
                confirmed: Some((keys, record)),
            })
        }
        None => Some(RemoteAgent {
            id: dto.id,
            name: t("remote.pending_name").to_string(),
            fingerprint,
            device: None,
            pending: true,
            last_seen: None,
            paired_at: None,
            confirmed: None,
        }),
    }
}

/// Open a request, hand it to the user, and relay the answer. Returns the
/// request id and the id of the question (0 when there is none), or `None`
/// for an agent that is not in the list.
fn take_request(dto: AgentRequestDto, agents: &[RemoteAgent]) -> Option<(String, u64)> {
    let (keys, record) = agents.iter().find(|a| a.id == dto.agent_id).and_then(|a| a.confirmed.as_ref())?;
    let id = dto.id.clone();
    let opened = {
        let guard = SESSION.peek();
        let session = guard.as_ref()?;
        agent_remote::open_request(session.keyset(), keys, &dto.id, &dto.request, now())
    };
    let opened = match opened {
        Ok(opened) => opened,
        // Not from the agent whose keys were confirmed, or garbled: refused
        // without a question, and the agent hears so.
        Err(_) => {
            spawn_forever(settle(dto.id, None, Err(AgentError::denied())));
            return Some((id, 0));
        }
    };
    let request = match Request::parse(&opened.method, Some(opened.params)) {
        Ok(request) if !request.browser_only() => request,
        Ok(_) => {
            spawn_forever(settle(dto.id, Some(opened.reply_key), Err(AgentError::method_not_found(&opened.method))));
            return Some((id, 0));
        }
        Err(e) => {
            spawn_forever(settle(dto.id, Some(opened.reply_key), Err(e)));
            return Some((id, 0));
        }
    };
    let identity = AgentIdentity::remote_agent(&dto.agent_id, &record.name, &record.version, &record.keys.ed25519);
    let (tx, rx) = futures_channel::oneshot::channel();
    let ui = agent_access::submit_remote(identity, request, tx);
    spawn_forever(relay(dto.id, ui, dto.expires_at, opened.reply_key, rx));
    Some((id, ui))
}

/// Wait for the user's answer and send it; after the request's time the
/// question goes.
async fn relay(
    request_id: String,
    ui: u64,
    expires_at: i64,
    reply_key: SymmetricKey,
    mut rx: futures_channel::oneshot::Receiver<Result<Value, AgentError>>,
) {
    loop {
        match rx.try_recv() {
            Ok(Some(result)) => {
                settle(request_id, Some(reply_key), result).await;
                return;
            }
            // The question was dropped: locked, or answered on another
            // device. A denial tells the agent now rather than at expiry.
            Err(_) => {
                settle(request_id, None, Err(AgentError::denied())).await;
                return;
            }
            Ok(None) if now() >= expires_at => {
                agent_access::withdraw(ui);
                return;
            }
            Ok(None) => platform::sleep_ms(250).await,
        }
    }
}

/// Send an answer (sealed with the reply key) or a denial. A 409 means
/// another device was first: nothing to do.
async fn settle(request_id: String, reply_key: Option<SymmetricKey>, result: Result<Value, AgentError>) {
    let Some(client) = client() else { return };
    let sent = match reply_key.and_then(|k| agent_remote::seal_answer(&k, &request_id, &result).ok()) {
        Some(answer) => client.answer_agent_request(&request_id, answer).await,
        None => client.deny_agent_request(&request_id).await,
    };
    match sent {
        Ok(()) => {}
        Err(e) if e.status() == Some(409) || e.is_not_found() => {}
        Err(e) => report_error(&e, |m| toast_err(&m)),
    }
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

/// The code's QR code as SVG, or nothing when it cannot be drawn.
fn qr_svg(text: &str) -> Option<String> {
    use qrcode::render::svg::Color;
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    Some(
        code.render::<Color>()
            .min_dimensions(200, 200)
            .quiet_zone(true)
            .dark_color(Color("#000000"))
            .light_color(Color("#ffffff"))
            .build(),
    )
}

/// Make a code, register it, and watch for the agent that pairs with it.
async fn pairing_task() {
    let made = {
        let guard = SESSION.peek();
        let Some(session) = guard.as_ref() else { return };
        let Some(link) = session.server() else { return };
        PairingCode::new(&link.url, &session.public_keys())
            .map_err(|e| e.to_string())
            .and_then(|code| client_for(session).map(|c| (code, c)).map_err(|e| client_error(&e)))
    };
    let failed =
        |message: String| Pairing { code: None, expires_at: 0, found: None, error: Some(message), busy: false };
    let (code, client) = match made {
        Ok(v) => v,
        Err(e) => {
            *PAIRING.write() = Some(failed(e));
            return;
        }
    };
    let expires_at = match client.create_agent_pairing(&code.token_hash()).await {
        Ok(r) => r.expires_at,
        Err(e) => {
            let message = if server_too_old(&e) { t("remote.server_old").to_string() } else { client_error(&e) };
            *PAIRING.write() = Some(failed(message));
            return;
        }
    };
    *PAIRING.write() = Some(Pairing { code: Some(code.clone()), expires_at, found: None, error: None, busy: false });
    let hash = code.token_hash();
    loop {
        platform::sleep_ms(3000).await;
        if !matches!(*MODAL.peek(), Some(Modal::PairAgent)) || PAIRING.peek().as_ref().is_none_or(|p| p.found.is_some())
        {
            return;
        }
        if now() >= expires_at {
            if let Some(p) = PAIRING.write().as_mut() {
                p.error = Some(t("remote.pair_expired").to_string());
            }
            return;
        }
        let Ok(agents) = client.agents().await else { continue };
        let Some(dto) = agents.into_iter().find(|a| a.token_hash.as_deref() == Some(hash.as_str())) else { continue };
        let found = {
            let guard = SESSION.peek();
            match guard.as_ref() {
                Some(session) => check_found(session, &code, dto),
                None => return,
            }
        };
        if let Some(p) = PAIRING.write().as_mut() {
            match found {
                Ok(found) => p.found = Some(found),
                Err(e) => p.error = Some(e),
            }
        }
        return;
    }
}

/// The agent that pairs proved it holds the code: its proof opens with the
/// account's keys and names the keys the server lists for it.
fn check_found(session: &Session, code: &PairingCode, dto: AgentDto) -> Result<Found, String> {
    let (Some(hash), Some(proof)) = (dto.token_hash.as_deref(), dto.proof.as_ref()) else {
        return Err(t("remote.pair_failed").to_string());
    };
    let proof =
        agent_remote::open_proof(session.keyset(), hash, proof).map_err(|_| t("remote.pair_failed").to_string())?;
    proof.check(code, &dto.keys).map_err(|_| t("remote.pair_mismatch").to_string())?;
    let fingerprint = dto.keys.fingerprint().map_err(|_| t("remote.pair_failed").to_string())?;
    Ok(Found {
        id: dto.id,
        name: clean_label(&proof.name, NAME_MAX),
        version: clean_label(&proof.version, 40),
        device: proof.device.as_deref().map(|d| clean_label(d, 60)).filter(|d| !d.is_empty()),
        fingerprint,
        keys: dto.keys,
    })
}

/// The owner confirms: the record every device can open goes to the server.
async fn confirm(found: Found) {
    if let Some(p) = PAIRING.write().as_mut() {
        p.busy = true;
    }
    let sealed = {
        let guard = SESSION.peek();
        let Some(session) = guard.as_ref() else { return };
        let record = AgentRecordData {
            name: found.name.clone(),
            version: found.version.clone(),
            keys: found.keys.clone(),
            fingerprint: found.fingerprint.clone(),
            paired_at: now(),
            device: found.device.clone(),
            paired_on: None,
        };
        let account_id = session.account().id.clone();
        record
            .seal(session.account_key(), &account_id, &found.id)
            .map_err(|e| core_error(&e))
            .and_then(|enc| client_for(session).map(|c| (c, enc)).map_err(|e| client_error(&e)))
    };
    let result = match sealed {
        Ok((client, enc)) => client.confirm_agent(&found.id, enc).await.map_err(|e| client_error(&e)),
        Err(e) => Err(e),
    };
    match result {
        Ok(()) => {
            *PAIRING.write() = None;
            *MODAL.write() = None;
            request_refresh();
            toast(&t("remote.paired_toast").replace("{name}", &found.name));
        }
        Err(e) => {
            if let Some(p) = PAIRING.write().as_mut() {
                p.busy = false;
                p.error = Some(e);
            }
        }
    }
}

/// Forget an agent elsewhere: the server stops relaying for it and tells it
/// so; its grants and log entries here go like a local agent's.
pub fn revoke(agent_id: String) {
    spawn_forever(async move {
        let Some(client) = client() else { return };
        match client.revoke_agent(&agent_id).await {
            Ok(()) => {
                agent_access::revoke(&agent_id);
                REMOTE.write().retain(|a| a.id != agent_id);
                request_refresh();
            }
            Err(e) => report_error(&e, |m| toast_err(&m)),
        }
    });
}

/// *Pair an agent*: the code to paste where the agent runs, then the agent
/// that pairs with it.
#[component]
pub fn PairAgentModal() -> Element {
    use_hook(|| {
        spawn_forever(async {
            *PAIRING.write() = None;
            pairing_task().await;
        });
    });
    let state = PAIRING.read().clone();
    let close = move |_| {
        *MODAL.write() = None;
        *PAIRING.write() = None;
    };
    let Some(state) = state else {
        return rsx! {
            ModalFrame { title: t("remote.pair_title"),
                p { class: "muted", {t("remote.pair_making")} }
                div { class: "row", style: "justify-content:flex-end",
                    button { class: "btn", onclick: close, {t("common.cancel")} }
                }
            }
        };
    };
    let (uri, text) = state.code.as_ref().map(|c| (c.uri(), c.text())).unwrap_or_default();
    let svg = qr_svg(&uri).unwrap_or_default();
    let left = (state.expires_at - now()).max(0);
    let minutes = format!("{}:{:02}", left / 60, left % 60);
    let (copy_text, copy_uri) = (text.clone(), uri.clone());
    rsx! {
        ModalFrame { title: t("remote.pair_title"),
            if let Some(error) = state.error.clone() {
                p { class: "danger-text", "{error}" }
                div { class: "row", style: "justify-content:flex-end",
                    button { class: "btn", onclick: close, {t("common.close")} }
                }
            } else if let Some(found) = state.found.clone() {
                p { {t("remote.pair_found").replace("{name}", &found.name)
                    .replace("{device}", found.device.as_deref().unwrap_or(t("remote.unknown_device")))} }
                div { class: "settings-row",
                    div { class: "k", div { class: "d", {t("remote.fingerprint_label")} } div { class: "t mono", "{found.fingerprint}" } }
                }
                p { class: "small muted", {t("remote.pair_compare")} }
                div { class: "row", style: "justify-content:flex-end;gap:8px",
                    button { class: "btn", onclick: close, {t("common.cancel")} }
                    button { class: "btn primary", disabled: state.busy,
                        onclick: move |_| { spawn_forever(confirm(found.clone())); },
                        {t("remote.pair_confirm")}
                    }
                }
            } else {
                p { {t("remote.pair_intro")} }
                pre { class: "code-block", "2secret agent pair \"{uri}\"" }
                div { class: "row", style: "gap:16px;align-items:flex-start;flex-wrap:wrap",
                    div { class: "qr-box", dangerous_inner_html: "{svg}" }
                    div { class: "col grow", style: "gap:8px;min-width:200px",
                        div { class: "small muted", {t("remote.pair_code_label")} }
                        div { class: "mono", style: "word-break:break-all;user-select:all", "{text}" }
                        div { class: "row", style: "gap:8px;flex-wrap:wrap",
                            button { class: "btn small", onclick: move |_| copy(copy_text.clone(), t("remote.pair_code_what")),
                                Icon { name: "copy", size: 14 } {t("remote.pair_copy_code")}
                            }
                            button { class: "btn small", onclick: move |_| copy(copy_uri.clone(), t("remote.pair_link_what")),
                                Icon { name: "copy", size: 14 } {t("remote.pair_copy_link")}
                            }
                        }
                        div { class: "small muted", {t("remote.pair_expires").replace("{time}", &minutes)} }
                        div { class: "small muted", {t("remote.pair_waiting")} }
                    }
                }
                div { class: "row", style: "justify-content:flex-end",
                    button { class: "btn", onclick: close, {t("common.cancel")} }
                }
            }
        }
    }
}

/// *Settings → Agents elsewhere*.
#[component]
pub fn RemoteAgentsSection() -> Element {
    let linked = SESSION.read().as_ref().is_some_and(|s| s.server().is_some() && s.server_token().is_some());
    let agents = REMOTE.read().clone();
    let error = REMOTE_ERROR.read().clone();
    // A tick a minute keeps the countdown and "last used" fresh.
    rsx! {
        div { class: "section",
            SectionHeading { text: t("remote.section") }
            div { class: "settings-row",
                div { class: "k",
                    div { class: "t", {t("remote.row")} }
                    div { class: "d", {t("remote.row_desc")} }
                    if !linked {
                        div { class: "d warn-text", {t("remote.needs_server")} }
                    } else if let Some(error) = error {
                        div { class: "d warn-text", "{error}" }
                    } else {
                        div { class: "d", {t("remote.setup")} }
                        pre { class: "code-block", "2secret mcp --remote" }
                    }
                    if linked {
                        if agents.is_empty() {
                            div { class: "d", {t("remote.none")} }
                        }
                        for agent in agents.iter().cloned() {
                            div { class: "row", key: "{agent.id}", style: "align-items:center;gap:8px;margin-top:4px",
                                div { class: "grow",
                                    div { "{agent.name} " span { class: "small muted mono", "{agent.fingerprint}" } }
                                    div { class: "small muted",
                                        if agent.pending {
                                            {t("remote.pending")}
                                        } else {
                                            if let Some(device) = agent.device.as_deref() {
                                                {t("remote.device").replace("{device}", device)} " · "
                                            }
                                            match agent.last_seen {
                                                Some(ts) => rsx! { {t("agent.last_used").replace("{time}", &relative_time(ts))} },
                                                None => rsx! { {t("remote.never_used")} },
                                            }
                                        }
                                    }
                                }
                                button { class: "btn small", onclick: move |_| revoke(agent.id.clone()), {t("agent.revoke")} }
                            }
                        }
                    }
                }
                if linked {
                    button { class: "btn small primary", onclick: move |_| { *MODAL.write() = Some(Modal::PairAgent); },
                        {t("remote.pair")}
                    }
                }
            }
        }
    }
}

#[component]
fn SectionHeading(text: String) -> Element {
    rsx! { div { class: "section-title", "{text}" } }
}
