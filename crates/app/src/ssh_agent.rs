//! Desktop: the SSH agent (*Settings → Desktop app*). `ssh`, `git` and other
//! programs log in and sign with the keys of SSH Key items through it; the
//! private keys stay in 2Secret. Every signature needs the user's consent in
//! 2Secret (or once for a key until 2Secret locks), and while the vault is
//! locked 2Secret asks to unlock it first.
//!
//! The agent listens on a Unix socket in the data directory (`agent.sock`;
//! `IdentityAgent` in `~/.ssh/config` or `SSH_AUTH_SOCK` points there), and on
//! Windows on the pipe of the OpenSSH agent (`\\.\pipe\openssh-ssh-agent`),
//! which the OpenSSH client of Windows uses.
//!
//! The listener and its connections run on their own threads. They list the
//! public keys the UI keeps up to date, and ask the UI, which holds the vault,
//! for every signature (`twosecret_core::ssh_agent` speaks the protocol).

use std::collections::HashSet;
use std::io::{Read, Write};
use std::sync::atomic::AtomicU64;
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;

use dioxus::prelude::*;
use tokio::sync::Notify;
use twosecret_core::ssh_agent::{self as protocol, AgentKey, Request};

use crate::i18n::t;
use crate::icons::{either, Icon};
use crate::state::*;

/// The public keys while the vault is unlocked (and the agent on).
static KEYS: Mutex<Option<Vec<AgentKey>>> = Mutex::new(None);
/// Signature requests for the UI.
static REQUESTS: Mutex<Vec<SignRequest>> = Mutex::new(Vec::new());
static REQUEST: Notify = Notify::const_new();
/// A client waits for the vault to be unlocked.
static UNLOCK: Notify = Notify::const_new();
/// Bumped to stop the running listener.
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// How long a client waits for an unlock or the user's answer.
const WAIT: Duration = Duration::from_secs(120);

struct SignRequest {
    key: AgentKey,
    data: Vec<u8>,
    flags: u32,
    /// The program that asks, as far as known.
    client: Option<String>,
    reply: mpsc::Sender<Option<Vec<u8>>>,
}

#[derive(Clone, PartialEq)]
pub enum Status {
    Off,
    Listening,
    /// Another agent (the OpenSSH service on Windows) has the address.
    InUse,
    Failed(String),
}

pub static STATUS: GlobalSignal<Status> = Signal::global(|| Status::Off);
/// Requests that wait for the user, oldest first.
static PROMPTS: GlobalSignal<Vec<Prompt>> = Signal::global(Vec::new);

#[derive(Clone)]
struct Prompt {
    id: u64,
    key: AgentKey,
    client: Option<String>,
    request: std::rc::Rc<std::cell::RefCell<Option<SignRequest>>>,
}

thread_local! {
    /// Keys allowed without asking until 2Secret locks.
    static ALLOWED: std::cell::RefCell<HashSet<String>> = std::cell::RefCell::new(HashSet::new());
    static NEXT_PROMPT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn keys() -> Option<Vec<AgentKey>> {
    KEYS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The keys, after the user unlocked the vault if it was locked.
fn wait_for_keys() -> Option<Vec<AgentKey>> {
    if let Some(keys) = keys() {
        return Some(keys);
    }
    UNLOCK.notify_one();
    let deadline = std::time::Instant::now() + WAIT;
    while std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        if let Some(keys) = keys() {
            return Some(keys);
        }
    }
    None
}

/// One client connection (its own thread).
fn serve(mut stream: impl Read + Write, client: Option<String>) {
    while let Ok(Some(message)) = protocol::read_message(&mut stream) {
        let answer = match protocol::parse(&message) {
            Request::Identities => protocol::identities_answer(&wait_for_keys().unwrap_or_default()),
            Request::Sign { key, data, flags } => {
                { ask_signature(key, data, flags, client.clone()).map(|s| protocol::sign_response(&s)) }
                    .unwrap_or_else(protocol::failure)
            }
            Request::Unsupported => protocol::failure(),
        };
        if protocol::write_message(&mut stream, &answer).is_err() {
            break;
        }
    }
}

fn ask_signature(blob: Vec<u8>, data: Vec<u8>, flags: u32, client: Option<String>) -> Option<Vec<u8>> {
    let key = wait_for_keys()?.into_iter().find(|k| k.blob == blob)?;
    let (reply, answer) = mpsc::channel();
    REQUESTS.lock().unwrap_or_else(|e| e.into_inner()).push(SignRequest { key, data, flags, client, reply });
    REQUEST.notify_one();
    answer.recv_timeout(WAIT).ok().flatten()
}

/// In the app component: the listener, the keys and the user's consent.
pub fn use_ssh_agent() {
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
                let requests = std::mem::take(&mut *REQUESTS.lock().unwrap_or_else(|e| e.into_inner()));
                for request in requests {
                    if ALLOWED.with_borrow(|a| a.contains(&request.key.item_id)) {
                        sign(request);
                    } else {
                        let id = NEXT_PROMPT.replace(NEXT_PROMPT.get() + 1);
                        PROMPTS.write().push(Prompt {
                            id,
                            key: request.key.clone(),
                            client: request.client.clone(),
                            request: std::rc::Rc::new(std::cell::RefCell::new(Some(request))),
                        });
                        crate::tray::show();
                    }
                }
            }
        });
    });
    // Start or stop with the setting (once the preferences are read).
    use_effect(|| {
        let phase = PHASE.read().clone();
        let on = PREFS.read().ssh_agent;
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
    // The keys of the unlocked vault; nothing is allowed after locking.
    use_effect(|| {
        let unlocked = *PHASE.read() == Phase::Unlocked && PREFS.read().ssh_agent;
        let keys = if unlocked {
            SESSION.read().as_ref().map(|s| protocol::keys(s.all_items().map(|(_, item)| item)))
        } else {
            None
        };
        *KEYS.lock().unwrap_or_else(|e| e.into_inner()) = keys;
        if !unlocked {
            ALLOWED.with_borrow_mut(HashSet::clear);
            if !PROMPTS.peek().is_empty() {
                // Dropping the requests refuses them.
                PROMPTS.write().clear();
            }
        }
    });
}

/// Sign with the item's key (off the UI thread) and answer the client.
fn sign(request: SignRequest) {
    touch();
    let item = SESSION.peek().as_ref().and_then(|s| s.item(&request.key.item_id).cloned());
    let Some(item) = item else {
        let _ = request.reply.send(None);
        return;
    };
    spawn(async move {
        let SignRequest { data, flags, reply, .. } = request;
        let signature = crate::platform::run_heavy(move || twosecret_core::ssh_agent::sign(&item, &data, flags)).await;
        if let Err(e) = &signature {
            toast_err(&e.to_string());
        }
        let _ = reply.send(signature.ok());
    });
}

/// The question to the user, above everything else.
#[component]
pub fn SshPrompt() -> Element {
    let mut remember = use_signal(|| false);
    let prompts = PROMPTS.read();
    let Some(prompt) = prompts.first().cloned() else { return rsx! {} };
    drop(prompts);
    let id = prompt.id;
    let mut answer = move |allow: bool| {
        let prompt = {
            let mut prompts = PROMPTS.write();
            let Some(at) = prompts.iter().position(|p| p.id == id) else { return };
            prompts.remove(at)
        };
        let Some(request) = prompt.request.borrow_mut().take() else { return };
        if allow {
            if remember() {
                ALLOWED.with_borrow_mut(|a| a.insert(prompt.key.item_id.clone()));
            }
            sign(request);
        } else {
            let _ = request.reply.send(None);
        }
        remember.set(false);
    };
    let who = prompt.client.clone().unwrap_or_else(|| t("ssh.someone").to_string());
    let text = t("ssh.ask").replace("{program}", &who).replace("{key}", &prompt.key.title);
    rsx! {
        div { class: "modal-backdrop",
            onkeydown: move |e: KeyboardEvent| {
                if e.key() == Key::Escape {
                    answer(false);
                }
            },
            div { class: "modal",
                div { class: "modal-head",
                    h3 { {t("ssh.title")} }
                    Icon { name: "terminal", size: 18 }
                }
                div { class: "modal-body col",
                    p { "{text}" }
                    div { class: "small muted mono", "{prompt.key.fingerprint}" }
                    label { class: "checkbox",
                        input { r#type: "checkbox", checked: remember(), onchange: move |e| remember.set(e.checked()) }
                        {t("ssh.remember")}
                    }
                }
                div { class: "modal-foot",
                    // The keyboard comes here, not to the buttons behind the
                    // question; Enter refuses, allowing takes a click.
                    button { class: "btn",
                        onmounted: move |e: MountedEvent| async move {
                            let _ = e.set_focus(true).await;
                        },
                        onclick: move |_| answer(false),
                        {t("ssh.deny")}
                    }
                    button { class: "btn primary", onclick: move |_| answer(true), {t("ssh.allow")} }
                }
            }
        }
    }
}

/// *Settings → Desktop app*.
#[component]
pub fn SshAgentRow() -> Element {
    let on = PREFS.read().ssh_agent;
    let status = STATUS.read().clone();
    let count = KEYS.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(Vec::len);
    // Read again when the vault changes.
    let _ = SESSION.read();
    let config = os::client_config();
    rsx! {
        div { class: "settings-row",
            div { class: "k",
                div { class: "t", {t("ssh.agent")} }
                div { class: "d", {t("ssh.agent_desc")} }
                match status {
                    Status::Listening => rsx! {
                        if let Some(count) = count {
                            div { class: "d", {t("ssh.keys").replace("{count}", &count.to_string())} }
                        }
                        div { class: "d", {t(os::SETUP)} }
                        pre { class: "code-block", "{config}" }
                    },
                    Status::InUse => rsx! { div { class: "d warn-text", {t(os::IN_USE)} } },
                    Status::Failed(e) => rsx! { div { class: "d danger-text", {t("ssh.failed").replace("{error}", &e)} } },
                    Status::Off => rsx! {},
                }
            }
            div { class: "row",
                if on && STATUS() == Status::Listening {
                    button { class: "btn small",
                        onclick: move |_| copy(os::client_config(), t("ssh.config")),
                        Icon { name: "copy", size: 14 }
                    }
                }
                button { class: either(on, "btn small", "btn small primary"),
                    onclick: move |_| {
                        PREFS.write().ssh_agent = !on;
                        save_prefs();
                    },
                    {either(on, t("common.turn_off"), t("common.turn_on"))}
                }
            }
        }
    }
}

#[cfg(unix)]
mod os {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;

    use super::GENERATION;

    pub const SETUP: &str = "ssh.setup_unix";
    pub const IN_USE: &str = "ssh.in_use_unix";

    fn socket() -> PathBuf {
        crate::platform::data_dir().join("agent.sock")
    }

    /// For `~/.ssh/config`, with `~` for the home folder.
    pub fn client_config() -> String {
        let path = socket().to_string_lossy().into_owned();
        let home = std::env::var("HOME").unwrap_or_default();
        let path = match path.strip_prefix(&home) {
            Some(rest) if !home.is_empty() => format!("~{rest}"),
            _ => path,
        };
        format!("Host *\n  IdentityAgent \"{path}\"")
    }

    /// `Err(None)`: another agent answers there.
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
                let client = client_name(&stream);
                std::thread::spawn(move || super::serve(stream, client));
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

    /// The program on the other end: `git (ssh)` when Git runs ssh.
    #[cfg(target_os = "linux")]
    fn client_name(stream: &UnixStream) -> Option<String> {
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
            return None;
        }
        let name = |pid: i32| std::fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|n| n.trim().to_string());
        let program = name(credentials.pid)?;
        let parent = std::fs::read_to_string(format!("/proc/{}/stat", credentials.pid))
            .ok()
            .and_then(|stat| stat.rsplit_once(')')?.1.split_whitespace().nth(1)?.parse::<i32>().ok())
            .and_then(name);
        Some(super::describe(program, parent))
    }

    #[cfg(target_os = "macos")]
    fn client_name(stream: &UnixStream) -> Option<String> {
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
            return None;
        }
        let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let n = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
        if n <= 0 {
            return None;
        }
        let path = String::from_utf8_lossy(&path[..n as usize]).into_owned();
        Some(path.rsplit('/').next().unwrap_or(&path).to_string())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn client_name(_stream: &UnixStream) -> Option<String> {
        None
    }
}

#[cfg(windows)]
mod os {
    use std::os::windows::io::FromRawHandle;
    use std::sync::atomic::Ordering;

    use windows::core::{HSTRING, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, HANDLE};
    use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::GENERATION;

    pub const SETUP: &str = "ssh.setup_windows";
    pub const IN_USE: &str = "ssh.in_use_windows";
    const PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

    pub fn client_config() -> String {
        "git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe".to_string()
    }

    fn create(first: bool) -> Option<HANDLE> {
        let flags = if first { PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE } else { PIPE_ACCESS_DUPLEX };
        let pipe = unsafe {
            CreateNamedPipeW(
                &HSTRING::from(PIPE),
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

    /// `Err(None)`: the OpenSSH agent service has the pipe.
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
                let client = client_name(pipe);
                let connection = pipe.0 as usize;
                std::thread::spawn(move || {
                    // Closes the pipe instance when done.
                    let stream = unsafe { std::fs::File::from_raw_handle(connection as *mut _) };
                    super::serve(stream, client);
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
        let _ = std::fs::OpenOptions::new().read(true).write(true).open(PIPE);
    }

    fn client_name(pipe: HANDLE) -> Option<String> {
        let mut pid = 0u32;
        unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) }.ok()?;
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let mut buffer = vec![0u16; 1024];
        let mut size = buffer.len() as u32;
        let named =
            unsafe { QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), &mut size) };
        let _ = unsafe { CloseHandle(process) };
        named.ok()?;
        let path = String::from_utf16_lossy(&buffer[..size as usize]);
        let name = path.rsplit('\\').next().unwrap_or(&path);
        Some(name.strip_suffix(".exe").unwrap_or(name).to_string())
    }
}

/// `git (ssh)` when a program (not a shell) runs ssh.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn describe(program: String, parent: Option<String>) -> String {
    const SHELLS: [&str; 7] = ["bash", "zsh", "fish", "sh", "dash", "tmux", "screen"];
    match parent {
        Some(parent) if program == "ssh" && !SHELLS.contains(&parent.as_str()) && !parent.is_empty() => {
            format!("{parent} (ssh)")
        }
        _ => program,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_the_program() {
        assert_eq!(describe("ssh".into(), Some("git".into())), "git (ssh)");
        assert_eq!(describe("ssh".into(), Some("zsh".into())), "ssh");
        assert_eq!(describe("ssh-keygen".into(), Some("git".into())), "ssh-keygen");
        assert_eq!(describe("ssh".into(), None), "ssh");
    }
}
