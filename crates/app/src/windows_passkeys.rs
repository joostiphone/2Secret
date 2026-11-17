//! Windows 11: 2Secret as a passkey provider (*Settings → Security →
//! Passkeys in Windows*). Edge, Chrome and other apps that create or use
//! passkeys through Windows (webauthn.dll) can then save them in 2Secret and
//! sign in with them, like with the passkey managers Windows 11 lists under
//! *Settings → Accounts → Passkeys → Advanced options*.
//!
//! Windows calls a COM object, `IPluginAuthenticator` from the plugin
//! authenticator API (`webauthnplugin.h`, `pluginauthenticator.idl` in
//! github.com/microsoft/webauthn), for every request. Windows only accepts a
//! provider that has package identity, and only starts one that a package
//! declares as its COM server. The setup therefore installs a small identity
//! package next to 2Secret (`windows/identity/`, a package "with external
//! location": it holds no files, only the identity, the COM server and the
//! folder of 2Secret). It is registered when the person turns this on, after
//! which 2Secret restarts once to run with that identity.
//!
//! The private keys never leave 2Secret. A request goes to the UI, which asks
//! the person (after unlocking, if 2Secret was locked) and answers with
//! `twosecret_core::passkey`. Windows Hello confirms the person once more
//! when 2Secret was already unlocked. Windows only gets, for its passkey
//! list and autofill, the website, user name and credential id of each
//! passkey.

// Only Windows uses most of this; elsewhere the UI calls the stubs.
#![cfg_attr(not(all(windows, feature = "desktop")), allow(dead_code))]

use twosecret_core::passkey::{SystemAssertion, SystemRequest};

/// Windows starts 2Secret with this argument (the COM server in
/// `windows/identity/AppxManifest.xml`) when it needs it for a request.
pub const ARG: &str = "--windows-passkeys";

/// Started by Windows for a passkey request: COM adds `-Embedding` to a
/// server it starts.
pub fn started_by_windows() -> bool {
    std::env::args()
        .skip(1)
        .any(|a| a == ARG || a.eq_ignore_ascii_case("-embedding") || a.eq_ignore_ascii_case("/embedding"))
}

/// A request from Windows in [`crate::state::PASSKEY`].
#[derive(Clone, Debug, PartialEq)]
pub struct SystemPasskey {
    pub request: SystemRequest,
    /// Ask Windows Hello before answering: 2Secret was unlocked already, so
    /// nobody has proven yet to be its owner for this request.
    pub verify_user: bool,
}

/// How the person answered a request from Windows.
pub enum Outcome {
    /// A new passkey, saved in the vault: its authenticator data.
    Created(Vec<u8>),
    Signed(SystemAssertion),
    Refused(Refusal),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Cancelled,
    /// The account already has one of the passkeys the website named.
    Exists,
    /// No passkey for the website (or none it accepts).
    NotFound,
    /// The website asks for a key type 2Secret does not make.
    NotSupported,
    /// Another request is open.
    Busy,
    TimedOut,
}

/// Why Windows Hello did not confirm the person.
pub enum Unverified {
    Cancelled,
    Failed(String),
}

/// Where this feature stands on this PC.
#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    /// Not Windows, or Windows without the plugin API (older than Windows 11
    /// 24H2 with the updates of November 2025).
    Unsupported,
    /// This installation has no identity package: built without a signing
    /// certificate, or not installed with the setup.
    NotInstalled,
    /// Off in 2Secret. `restart`: turning it on restarts 2Secret, which does
    /// not run with its package identity yet.
    Off {
        restart: bool,
    },
    /// Registered with Windows, but turned off in Windows Settings.
    OffInWindows,
    On,
}

pub use imp::*;

#[cfg(all(windows, feature = "desktop"))]
mod imp {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::{Mutex, MutexGuard};
    use std::time::Duration;

    use dioxus::prelude::*;
    use tokio::sync::Notify;
    use twosecret_core::passkey::SystemRequest;
    use windows::core::{GUID, HRESULT, HSTRING, PWSTR};
    use windows::Win32::Foundation::{
        APPMODEL_ERROR_NO_PACKAGE, ERROR_BUSY, ERROR_INSUFFICIENT_BUFFER, ERROR_TIMEOUT, E_INVALIDARG, E_UNEXPECTED,
        NTE_BAD_SIGNATURE, NTE_EXISTS, NTE_NOT_FOUND, NTE_NOT_SUPPORTED, NTE_USER_CANCELLED, S_OK,
    };
    use windows::Win32::Storage::Packaging::Appx::GetCurrentPackageFullName;
    use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

    use super::{Outcome, Refusal, Status, SystemPasskey, Unverified};
    use crate::extension::PasskeyRequest;
    use crate::i18n::t;
    use crate::state::*;

    /// The COM class of 2Secret's `IPluginAuthenticator`. The identity
    /// package declares the same (`windows/identity/AppxManifest.xml`).
    pub(super) const CLSID: GUID = GUID::from_u128(0x5adf0732_2a4e_4752_bdd2_ed9260b39f46);
    /// The identity package next to the program (the setup installs it).
    const PACKAGE_FILE: &str = "2Secret-identity.msix";
    /// `Version` in `windows/identity/AppxManifest.xml`: a newer package is
    /// registered again.
    const PACKAGE_VERSION: &str = "1.0.0.0";
    /// How long a request waits for the person; Windows usually gives up
    /// sooner and cancels it.
    const WAIT: Duration = Duration::from_secs(600);

    /// A request on its way from a COM thread to the UI.
    struct Incoming {
        rid: String,
        transaction_id: GUID,
        request: SystemRequest,
        reply: mpsc::Sender<Outcome>,
    }

    /// The request Windows waits for (one at a time).
    struct Pending {
        transaction_id: GUID,
        rid: String,
        reply: mpsc::Sender<Outcome>,
    }

    static INCOMING: Mutex<Vec<Incoming>> = Mutex::new(Vec::new());
    static INCOMING_READY: Notify = Notify::const_new();
    static PENDING: Mutex<Option<Pending>> = Mutex::new(None);
    /// Requests that ended without the UI (cancelled, timed out).
    static ENDED: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static ENDED_READY: Notify = Notify::const_new();
    /// What the UI answers to, by request id.
    static REPLIES: Mutex<Vec<(String, GUID, mpsc::Sender<Outcome>)>> = Mutex::new(Vec::new());
    /// For `GetLockStatus`, which Windows asks from a COM thread.
    pub(super) static UNLOCKED: AtomicBool = AtomicBool::new(false);
    /// The last thing that went wrong, for *Settings*: requests come from
    /// Windows, which tells the person little.
    static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);
    /// The credential metadata Windows has from this 2Secret.
    static SYNCED: Mutex<Option<Vec<Metadata>>> = Mutex::new(None);
    /// The metadata Windows should get next, and the turn of the thread
    /// that gives it: one replaces Windows' list at a time.
    static WANTED: Mutex<Option<Vec<Metadata>>> = Mutex::new(None);
    static SYNCING: Mutex<()> = Mutex::new(());

    pub static STATUS: GlobalSignal<Option<Status>> = Signal::global(|| None);
    static ERROR_SHOWN: GlobalSignal<Option<String>> = Signal::global(|| None);

    thread_local! {
        /// Whether the window was visible before a request showed it.
        static WAS_VISIBLE: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
    }

    fn held<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(super) fn note_error(text: String) {
        *held(&LAST_ERROR) = Some(text);
    }

    fn com_thread() {
        // Fails harmlessly when this thread is in an apartment already.
        let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    }

    /// The identity package's full name when 2Secret runs with it.
    fn package_full_name() -> Option<String> {
        let mut length = 0u32;
        let first = unsafe { GetCurrentPackageFullName(&mut length, None) };
        if first == APPMODEL_ERROR_NO_PACKAGE || first != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
        let mut buffer = vec![0u16; length as usize];
        let second = unsafe { GetCurrentPackageFullName(&mut length, Some(PWSTR(buffer.as_mut_ptr()))) };
        if second.0 != 0 {
            return None;
        }
        let end = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
        Some(String::from_utf16_lossy(&buffer[..end]))
    }

    fn install_dir() -> Option<std::path::PathBuf> {
        Some(std::env::current_exe().ok()?.parent()?.to_path_buf())
    }

    fn package_file() -> Option<std::path::PathBuf> {
        install_dir().map(|d| d.join(PACKAGE_FILE)).filter(|p| p.is_file())
    }

    /// At start, before the window: answer Windows from now on. Only with
    /// package identity, which Windows needs (and COM for the declared
    /// server), and where the plugin API exists.
    pub fn start() {
        if package_full_name().is_none() || ffi::api().is_none() {
            return;
        }
        let (ready, registered) = mpsc::channel();
        std::thread::spawn(move || com::serve(ready));
        // Before WebView2 starts: COM's security settings are taken from the
        // first call that sets them, for the whole process.
        if !registered.recv_timeout(Duration::from_secs(10)).unwrap_or(false) {
            note_error("COM: the passkey provider could not be registered".into());
        }
    }

    /// Run on a COM thread for every request: decode, check, ask the person,
    /// encode the answer.
    pub(super) unsafe fn operation(
        create: bool,
        request: *const ffi::OperationRequest,
        response: *mut ffi::OperationResponse,
    ) -> HRESULT {
        if request.is_null() || response.is_null() {
            return E_INVALIDARG;
        }
        // An [out] value is marshaled even on failure: leave it empty.
        unsafe {
            response.write(ffi::OperationResponse { cb_encoded_response: 0, pb_encoded_response: std::ptr::null_mut() })
        };
        let Some(api) = ffi::api() else { return E_UNEXPECTED };
        let request = unsafe { &*request };
        let encoded = unsafe { ffi::bytes(request.pb_encoded_request, request.cb_encoded_request) };
        let signature = unsafe { ffi::bytes(request.pb_request_signature, request.cb_request_signature) };
        if request.request_type != ffi::REQUEST_TYPE_CTAP2_CBOR || encoded.is_empty() {
            return E_INVALIDARG;
        }
        // Only Windows can sign: any other program may call this COM object.
        if let Err(e) = unsafe { ffi::verify_request(api, encoded, signature) } {
            note_error(format!("refused a request that Windows did not sign: {e}"));
            return NTE_BAD_SIGNATURE;
        }
        let decoded = if create {
            unsafe { ffi::decode_creation(api, encoded) }
        } else {
            unsafe { ffi::decode_sign_in(api, encoded) }
        };
        let system = match decoded {
            Ok(system) => system,
            Err(hr) => {
                note_error(format!("could not read the request: {}", hresult_text(hr)));
                return hr;
            }
        };
        match (ask(request.transaction_id, system), create) {
            (Outcome::Created(auth_data), true) => unsafe { ffi::encode_created(api, &auth_data, response) },
            (Outcome::Signed(assertion), false) => unsafe { ffi::encode_signed(api, &assertion, response) },
            (Outcome::Refused(refusal), _) => refusal_code(refusal),
            _ => E_UNEXPECTED,
        }
    }

    fn refusal_code(refusal: Refusal) -> HRESULT {
        match refusal {
            // Windows tells cancelling apart from errors by this code.
            Refusal::Cancelled => NTE_USER_CANCELLED,
            Refusal::Exists => NTE_EXISTS,
            Refusal::NotFound => NTE_NOT_FOUND,
            Refusal::NotSupported => NTE_NOT_SUPPORTED,
            Refusal::Busy => ERROR_BUSY.to_hresult(),
            Refusal::TimedOut => ERROR_TIMEOUT.to_hresult(),
        }
    }

    /// Hand the request to the UI and wait for the person.
    fn ask(transaction_id: GUID, request: SystemRequest) -> Outcome {
        let rid = format!("{transaction_id:?}");
        let (reply, answer) = mpsc::channel();
        {
            let mut pending = held(&PENDING);
            if pending.is_some() {
                return Outcome::Refused(Refusal::Busy);
            }
            *pending = Some(Pending { transaction_id, rid: rid.clone(), reply: reply.clone() });
        }
        held(&INCOMING).push(Incoming { rid: rid.clone(), transaction_id, request, reply });
        INCOMING_READY.notify_one();
        let outcome = answer.recv_timeout(WAIT).unwrap_or(Outcome::Refused(Refusal::TimedOut));
        *held(&PENDING) = None;
        // Closes the question if the person did not answer it.
        held(&ENDED).push(rid);
        ENDED_READY.notify_one();
        outcome
    }

    /// `CancelOperation`, from a COM thread: Windows closed its dialog or
    /// gave up.
    pub(super) fn cancel(transaction_id: GUID) -> HRESULT {
        let pending = held(&PENDING);
        match pending.as_ref() {
            Some(p) if p.transaction_id == transaction_id => {
                let _ = p.reply.send(Outcome::Refused(Refusal::Cancelled));
                held(&ENDED).push(p.rid.clone());
                ENDED_READY.notify_one();
                S_OK
            }
            _ => NTE_NOT_FOUND,
        }
    }

    /// The person answered in the UI.
    pub fn answer(rid: &str, outcome: Outcome) {
        let reply = {
            let mut replies = held(&REPLIES);
            replies.iter().position(|(r, _, _)| r == rid).map(|at| replies.remove(at).2)
        };
        if let Some(reply) = reply {
            let _ = reply.send(outcome);
        }
        restore_window();
    }

    /// Back to what the person had before the request: the window hides
    /// again if it was hidden in the system tray.
    fn restore_window() {
        let tray = PREFS.peek().tray && crate::tray::supported();
        if !WAS_VISIBLE.get() && tray {
            dioxus::desktop::window().set_visible(false);
        }
        WAS_VISIBLE.set(true);
    }

    /// Windows Hello for the request `rid`, in front of 2Secret's window.
    pub async fn verify_user(rid: &str, user_name: &str, hint: &str) -> Result<(), Unverified> {
        use dioxus::desktop::tao::platform::windows::WindowExtWindows;
        let transaction_id = held(&REPLIES).iter().find(|(r, _, _)| r == rid).map(|(_, id, _)| *id);
        let Some(transaction_id) = transaction_id else { return Err(Unverified::Cancelled) };
        let Some(api) = ffi::api() else { return Err(Unverified::Failed("webauthn.dll".into())) };
        let hwnd = dioxus::desktop::window().window.hwnd();
        let (user_name, hint) = (user_name.to_string(), hint.to_string());
        let result = crate::platform::run_heavy(move || {
            com_thread();
            crate::biometric::focus_prompt();
            unsafe { ffi::verify_user(api, hwnd, &transaction_id, &user_name, &hint) }
        })
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(hr) if hr == NTE_USER_CANCELLED => Err(Unverified::Cancelled),
            Err(hr) => Err(Unverified::Failed(hresult_text(hr))),
        }
    }

    pub(super) fn hresult_text(hr: HRESULT) -> String {
        format!("{} ({:#010x})", hr.message(), hr.0 as u32)
    }

    /// The website, user and credential id of a passkey, for Windows' list.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub(super) struct Metadata {
        pub credential_id: Vec<u8>,
        pub rp_id: String,
        pub rp_name: String,
        pub user_id: Vec<u8>,
        pub user_name: String,
        pub user_display_name: String,
    }

    fn metadata(session: &twosecret_core::session::Session) -> Vec<Metadata> {
        let decode = |v: &str| twosecret_core::util::unb64url(v.trim_end_matches('=')).ok();
        let mut list: Vec<Metadata> = session
            .all_items()
            .filter(|(_, item)| !item.is_trashed())
            .flat_map(|(_, item)| item.passkeys.iter())
            .filter_map(|p| {
                Some(Metadata {
                    credential_id: decode(&p.credential_id)?,
                    rp_id: p.rp_id.clone(),
                    rp_name: if p.rp_name.is_empty() { p.rp_id.clone() } else { p.rp_name.clone() },
                    user_id: decode(&p.user_handle)?,
                    user_name: p.user_name.clone(),
                    user_display_name: p.user_display_name.clone(),
                })
            })
            .collect();
        list.sort_by(|a, b| a.credential_id.cmp(&b.credential_id));
        // A passkey in two items (a duplicated login) once: Windows refuses
        // the whole list otherwise.
        list.dedup_by(|a, b| a.credential_id == b.credential_id);
        list
    }

    /// Give Windows the metadata of the vault's passkeys (never their keys),
    /// unless it has that already.
    fn sync(list: Vec<Metadata>) {
        if held(&SYNCED).as_ref() == Some(&list) {
            return;
        }
        let Some(api) = ffi::api() else { return };
        *held(&WANTED) = Some(list);
        std::thread::spawn(move || {
            let _turn = held(&SYNCING);
            // A later change may have come meanwhile: give the newest list.
            let Some(list) = held(&WANTED).take() else { return };
            if held(&SYNCED).as_ref() == Some(&list) {
                return;
            }
            com_thread();
            match unsafe { ffi::replace_credentials(api, &list) } {
                Ok(()) => *held(&SYNCED) = Some(list),
                Err(hr) => {
                    *held(&SYNCED) = None;
                    note_error(format!("could not update Windows' passkey list: {}", hresult_text(hr)))
                }
            }
        });
    }

    /// Forget this device: Windows forgets the passkeys from 2Secret too.
    pub fn forget() {
        let Some(api) = ffi::api() else { return };
        if package_full_name().is_none() {
            return;
        }
        *held(&WANTED) = None;
        std::thread::spawn(move || {
            let _turn = held(&SYNCING);
            com_thread();
            let _ = unsafe { (api.remove_all_credentials)(&CLSID) };
            *held(&SYNCED) = None;
        });
    }

    /// Where this stands; asks Windows, so not on the UI thread.
    fn status() -> Status {
        let Some(api) = ffi::api() else { return Status::Unsupported };
        if package_full_name().is_none() {
            return if package_file().is_some() { Status::Off { restart: true } } else { Status::NotInstalled };
        }
        com_thread();
        let mut state = 0i32;
        let hr = unsafe { (api.get_state)(&CLSID, &mut state) };
        match (hr.is_ok(), state) {
            // Not registered (NTE_NOT_FOUND) or not readable: off.
            (false, _) => Status::Off { restart: false },
            (true, ffi::AUTHENTICATOR_STATE_ENABLED) => Status::On,
            (true, _) => Status::OffInWindows,
        }
    }

    /// 2Secret runs with an older identity package than the one next to it.
    fn outdated() -> bool {
        // "Name_Version_Architecture_ResourceId_PublisherId"
        let version = package_full_name().and_then(|name| name.split('_').nth(1).map(str::to_string));
        version.is_some_and(|v| v != PACKAGE_VERSION) && package_file().is_some()
    }

    fn refresh() {
        spawn(async move {
            let status = crate::platform::run_heavy(status).await;
            *STATUS.write() = Some(status);
            *ERROR_SHOWN.write() = held(&LAST_ERROR).clone();
        });
    }

    /// Register the identity package (for this user, connected to this
    /// folder) and start 2Secret again, which then runs with its identity.
    fn register_package() -> Result<(), String> {
        use windows::Foundation::Uri;
        use windows::Management::Deployment::{AddPackageOptions, PackageManager};
        let dir = install_dir().ok_or("no program folder")?;
        let package = package_file().ok_or_else(|| t("winpasskeys.not_installed").to_string())?;
        com_thread();
        let run = || -> windows::core::Result<(HRESULT, String)> {
            let options = AddPackageOptions::new()?;
            options.SetExternalLocationUri(&Uri::CreateUri(&HSTRING::from(file_uri(&dir)))?)?;
            // An update of the package while 2Secret runs with the old one.
            options.SetDeferRegistrationWhenPackagesAreInUse(true)?;
            let manager = PackageManager::new()?;
            let result =
                manager.AddPackageByUriAsync(&Uri::CreateUri(&HSTRING::from(file_uri(&package)))?, &options)?.get()?;
            Ok((result.ExtendedErrorCode()?, result.ErrorText()?.to_string()))
        };
        let (code, text) = run().map_err(|e| package_error(e.code(), &e.message()))?;
        if code.is_err() {
            return Err(package_error(code, &text));
        }
        Ok(())
    }

    fn package_error(code: HRESULT, text: &str) -> String {
        // CERT_E_UNTRUSTEDROOT: the package is signed with a certificate this
        // PC does not trust (a test certificate, CONTRIBUTING.md).
        if code.0 as u32 == 0x800B_0109 {
            return t("winpasskeys.untrusted").to_string();
        }
        format!("{} ({:#010x})", text.trim(), code.0 as u32)
    }

    /// `file:///C:/Users/...`, as the package manager wants its paths.
    fn file_uri(path: &std::path::Path) -> String {
        super::file_uri(&path.to_string_lossy())
    }

    /// Quit and start again once this process has ended (the identity
    /// applies from the start of a process).
    fn restart() {
        use std::os::windows::process::CommandExt;
        let Ok(exe) = std::env::current_exe() else { return };
        let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
        let script = format!(
            "$ErrorActionPreference = 'SilentlyContinue'\nWait-Process -Id {} -Timeout 30\nStart-Process -FilePath {}\n",
            std::process::id(),
            quote(&exe.to_string_lossy())
        );
        let encoded: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let started = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"])
            .arg(twosecret_core::util::b64(&encoded))
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
        if started.is_ok() {
            crate::tray::remove();
            std::process::exit(0);
        }
    }

    fn add_authenticator() -> Result<(), String> {
        let api = ffi::api().ok_or("webauthn.dll")?;
        com_thread();
        unsafe { ffi::add_authenticator(api) }.map_err(hresult_text)
    }

    fn remove_authenticator() -> Result<(), String> {
        let api = ffi::api().ok_or("webauthn.dll")?;
        com_thread();
        *held(&SYNCED) = None;
        let _ = unsafe { (api.remove_all_credentials)(&CLSID) };
        let hr = unsafe { (api.remove)(&CLSID) };
        if hr.is_ok() || hr == NTE_NOT_FOUND {
            Ok(())
        } else {
            Err(hresult_text(hr))
        }
    }

    /// A request from Windows: show it (after unlocking, if need be).
    fn receive(incoming: Incoming) {
        let Incoming { rid, transaction_id, request, reply } = incoming;
        if PASSKEY.peek().is_some() {
            let _ = reply.send(Outcome::Refused(Refusal::Busy));
            return;
        }
        // No account to save in or sign in with.
        if *PHASE.peek() == Phase::Welcome {
            let _ = reply.send(Outcome::Refused(Refusal::NotFound));
            return;
        }
        held(&REPLIES).push((rid.clone(), transaction_id, reply));
        let kind = match request {
            SystemRequest::Create(_) => "create",
            SystemRequest::SignIn(_) => "get",
        };
        let verify_user = *PHASE.peek() == Phase::Unlocked;
        *PASSKEY.write() = Some(PasskeyRequest {
            rid,
            kind: kind.into(),
            origin: request.rp_id().to_string(),
            options: serde_json::Value::Null,
            system: Some(SystemPasskey { request, verify_user }),
        });
        WAS_VISIBLE.set(dioxus::desktop::window().is_visible());
        crate::tray::show();
    }

    /// Windows cancelled, or the request timed out: close its question.
    fn ended(rid: String) {
        let open = held(&REPLIES).iter().position(|(r, _, _)| *r == rid);
        if let Some(at) = open {
            held(&REPLIES).remove(at);
        }
        if PASSKEY.peek().as_ref().is_some_and(|p| p.system.is_some() && p.rid == rid) {
            *PASSKEY.write() = None;
            restore_window();
        }
    }

    /// In the app component: requests, the lock status for Windows and
    /// Windows' list of passkeys.
    pub fn use_windows_passkeys() {
        use_hook(|| {
            spawn(async {
                loop {
                    INCOMING_READY.notified().await;
                    let incoming = std::mem::take(&mut *held(&INCOMING));
                    for request in incoming {
                        receive(request);
                    }
                }
            });
            spawn(async {
                loop {
                    ENDED_READY.notified().await;
                    let rids = std::mem::take(&mut *held(&ENDED));
                    for rid in rids {
                        ended(rid);
                    }
                }
            });
        });
        // Once the preferences are read: finish turning on after the
        // restart, and register a newer identity package.
        use_effect(|| {
            if *PHASE.read() == Phase::Loading || STATUS.peek().is_some() {
                return;
            }
            let wanted = PREFS.peek().windows_passkeys;
            spawn(async move {
                if wanted && crate::platform::run_heavy(outdated).await {
                    // Deferred while 2Secret runs: Windows switches at the
                    // next start.
                    if let Err(e) = crate::platform::run_heavy(register_package).await {
                        note_error(e);
                    }
                }
                let current = crate::platform::run_heavy(status).await;
                let current = match current {
                    Status::Off { restart: false } if wanted && package_full_name().is_some() => {
                        match crate::platform::run_heavy(add_authenticator).await {
                            Ok(()) => {
                                // Just restarted for this: on to the switch in Windows.
                                open_windows_settings();
                                crate::platform::run_heavy(status).await
                            }
                            Err(e) => {
                                note_error(e);
                                current
                            }
                        }
                    }
                    current => current,
                };
                *STATUS.write() = Some(current);
                *ERROR_SHOWN.write() = held(&LAST_ERROR).clone();
            });
        });
        use_effect(|| {
            let phase = PHASE.read().clone();
            UNLOCKED.store(phase == Phase::Unlocked, Ordering::SeqCst);
            // No account to save in or sign in with.
            if phase == Phase::Welcome {
                let rid = PASSKEY.peek().as_ref().filter(|p| p.system.is_some()).map(|p| p.rid.clone());
                if let Some(rid) = rid {
                    *PASSKEY.write() = None;
                    answer(&rid, Outcome::Refused(Refusal::NotFound));
                }
            }
        });
        use_effect(|| {
            let registered = matches!(*STATUS.read(), Some(Status::On | Status::OffInWindows));
            if !registered || !PREFS.read().windows_passkeys {
                return;
            }
            let list = SESSION.read().as_ref().map(metadata);
            // Locked: Windows keeps the list, and asks to unlock when a
            // passkey from it is chosen.
            if let Some(list) = list {
                sync(list);
            }
        });
    }

    fn turn_on() {
        PREFS.write().windows_passkeys = true;
        save_prefs();
        *held(&LAST_ERROR) = None;
        spawn(async move {
            if package_full_name().is_none() {
                match crate::platform::run_heavy(register_package).await {
                    Ok(()) => {
                        toast(t("winpasskeys.restarting"));
                        crate::platform::sleep_ms(1200).await;
                        restart();
                        toast_err(t("winpasskeys.restart_failed"));
                    }
                    Err(e) => {
                        note_error(e.clone());
                        toast_err(&e);
                    }
                }
                refresh();
                return;
            }
            match crate::platform::run_heavy(add_authenticator).await {
                // Windows asks for Windows Hello as the person turns it on there.
                Ok(()) => open_windows_settings(),
                Err(e) => {
                    note_error(e.clone());
                    toast_err(&e);
                }
            }
            refresh();
        });
    }

    fn turn_off() {
        PREFS.write().windows_passkeys = false;
        save_prefs();
        spawn(async move {
            if let Err(e) = crate::platform::run_heavy(remove_authenticator).await {
                note_error(e.clone());
                toast_err(&e);
            }
            refresh();
        });
    }

    fn open_windows_settings() {
        // The page with the passkey providers.
        let _ = std::process::Command::new("explorer.exe").arg("ms-settings:passkeys-advancedoptions").spawn();
    }

    /// *Settings → Security → Passkeys in Windows*.
    #[component]
    pub fn SettingsRow() -> Element {
        use crate::icons::either;
        use_hook(refresh);
        let status = STATUS.read().clone();
        let error = ERROR_SHOWN.read().clone();
        let desc = match &status {
            None => "",
            Some(Status::Unsupported) => t("winpasskeys.unsupported"),
            Some(Status::NotInstalled) => t("winpasskeys.not_installed"),
            Some(Status::Off { restart: true }) => t("winpasskeys.desc_restart"),
            Some(Status::Off { .. }) => t("winpasskeys.desc"),
            Some(Status::OffInWindows) => t("winpasskeys.in_windows"),
            Some(Status::On) => t("winpasskeys.on"),
        };
        let switchable = matches!(status, Some(Status::Off { .. } | Status::OffInWindows | Status::On));
        // Wanted but not registered (it failed): "Turn on" tries again.
        let on = matches!(status, Some(Status::OffInWindows | Status::On));
        rsx! {
            div { class: "settings-row",
                div { class: "k",
                    div { class: "t", {t("winpasskeys.title")} }
                    div { class: "d", {desc} }
                    if let Some(error) = error {
                        div { class: "d danger-text", {t("winpasskeys.error").replace("{error}", &error)} }
                    }
                }
                div { class: "row",
                    if matches!(status, Some(Status::OffInWindows | Status::On)) {
                        button { class: either(status == Some(Status::OffInWindows), "btn small primary", "btn small"),
                            onclick: move |_| open_windows_settings(),
                            {t("winpasskeys.open_settings")}
                        }
                    }
                    if switchable {
                        button { class: either(on, "btn small", "btn small primary"),
                            onclick: move |_| if on { turn_off() } else { turn_on() },
                            {either(on, t("common.turn_off"), t("common.turn_on"))}
                        }
                    }
                }
            }
        }
    }

    mod com {
        //! The COM server: a class factory for `IPluginAuthenticator`, in
        //! the multithreaded apartment, so a request may wait for the
        //! person without holding up the window.
        #![allow(non_snake_case)]

        use std::ffi::c_void;
        use std::sync::atomic::Ordering;
        use std::sync::mpsc;

        use windows::core::{implement, interface, IUnknown, IUnknown_Vtbl, Interface, Ref, BOOL, GUID, HRESULT};
        use windows::Win32::Foundation::{CLASS_E_NOAGGREGATION, E_INVALIDARG, E_POINTER, E_UNEXPECTED, S_OK};
        use windows::Win32::System::Com::{
            CoInitializeEx, CoInitializeSecurity, CoRegisterClassObject, IClassFactory, IClassFactory_Impl,
            CLSCTX_LOCAL_SERVER, COINIT_MULTITHREADED, EOAC_NONE, REGCLS_MULTIPLEUSE, RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
        };

        use super::ffi::{CancelOperationRequest, OperationRequest, OperationResponse};

        /// `pluginauthenticator.idl`: four methods after IUnknown's, in
        /// this order.
        #[interface("d26bcf6f-b54c-43ff-9f06-d5bf148625f7")]
        unsafe trait IPluginAuthenticator: IUnknown {
            fn MakeCredential(&self, request: *const OperationRequest, response: *mut OperationResponse) -> HRESULT;
            fn GetAssertion(&self, request: *const OperationRequest, response: *mut OperationResponse) -> HRESULT;
            fn CancelOperation(&self, request: *const CancelOperationRequest) -> HRESULT;
            fn GetLockStatus(&self, status: *mut i32) -> HRESULT;
        }

        /// A panic must not unwind into Windows.
        fn guarded(f: impl FnOnce() -> HRESULT) -> HRESULT {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(E_UNEXPECTED)
        }

        #[implement(IPluginAuthenticator)]
        struct Authenticator;

        impl IPluginAuthenticator_Impl for Authenticator_Impl {
            unsafe fn MakeCredential(
                &self,
                request: *const OperationRequest,
                response: *mut OperationResponse,
            ) -> HRESULT {
                guarded(|| unsafe { super::operation(true, request, response) })
            }

            unsafe fn GetAssertion(
                &self,
                request: *const OperationRequest,
                response: *mut OperationResponse,
            ) -> HRESULT {
                guarded(|| unsafe { super::operation(false, request, response) })
            }

            unsafe fn CancelOperation(&self, request: *const CancelOperationRequest) -> HRESULT {
                if request.is_null() {
                    return E_INVALIDARG;
                }
                let transaction_id = unsafe { (*request).transaction_id };
                guarded(|| super::cancel(transaction_id))
            }

            unsafe fn GetLockStatus(&self, status: *mut i32) -> HRESULT {
                if status.is_null() {
                    return E_POINTER;
                }
                let unlocked = super::UNLOCKED.load(Ordering::SeqCst);
                unsafe { status.write(if unlocked { super::ffi::PLUGIN_UNLOCKED } else { super::ffi::PLUGIN_LOCKED }) };
                S_OK
            }
        }

        #[implement(IClassFactory)]
        struct Factory;

        impl IClassFactory_Impl for Factory_Impl {
            fn CreateInstance(
                &self,
                outer: Ref<'_, IUnknown>,
                iid: *const GUID,
                object: *mut *mut c_void,
            ) -> windows::core::Result<()> {
                if object.is_null() || iid.is_null() {
                    return Err(E_POINTER.into());
                }
                unsafe { object.write(std::ptr::null_mut()) };
                if !outer.is_null() {
                    return Err(CLASS_E_NOAGGREGATION.into());
                }
                let authenticator: IPluginAuthenticator = Authenticator.into();
                unsafe { authenticator.query(iid, object) }.ok()
            }

            fn LockServer(&self, _lock: BOOL) -> windows::core::Result<()> {
                Ok(())
            }
        }

        /// The COM thread: register the class and keep the apartment (and
        /// with it the registration) for as long as 2Secret runs.
        pub fn serve(ready: mpsc::Sender<bool>) {
            let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            // As Microsoft's passkey manager sample does. Fails when
            // something in this process set it already; COM then keeps that.
            let _ = unsafe {
                CoInitializeSecurity(
                    None,
                    -1,
                    None,
                    None,
                    RPC_C_AUTHN_LEVEL_DEFAULT,
                    RPC_C_IMP_LEVEL_IMPERSONATE,
                    None,
                    EOAC_NONE,
                    None,
                )
            };
            let factory: IClassFactory = Factory.into();
            let registered =
                unsafe { CoRegisterClassObject(&super::CLSID, &factory, CLSCTX_LOCAL_SERVER, REGCLS_MULTIPLEUSE) };
            let _ = ready.send(registered.is_ok());
            if registered.is_err() {
                return;
            }
            loop {
                std::thread::park();
            }
        }
    }

    pub(super) mod ffi {
        //! The plugin authenticator API of webauthn.dll, loaded at run time:
        //! Windows before 11 24H2 (with the updates of late 2025) lacks it.
        //! The structures follow `webauthn.h` (API version 9),
        //! `webauthnplugin.h` and `pluginauthenticator.h` from
        //! github.com/microsoft/webauthn field by field; the tests at the
        //! bottom check their sizes and offsets on 64-bit Windows.
        #![allow(non_snake_case)]

        use std::ffi::c_void;
        use std::ptr::{null, null_mut};
        use std::sync::OnceLock;

        use twosecret_core::passkey::{SystemAssertion, SystemCreation, SystemRequest, SystemSignIn};
        use windows::core::{s, w, GUID, HRESULT};
        use windows::Win32::Foundation::{E_INVALIDARG, E_UNEXPECTED, NTE_EXISTS, S_OK};
        use windows::Win32::Security::Cryptography::{
            NCryptFreeObject, NCryptImportKey, NCryptOpenStorageProvider, NCryptVerifySignature,
            BCRYPT_PSS_PADDING_INFO, BCRYPT_PUBLIC_KEY_BLOB, BCRYPT_RSAPUBLIC_MAGIC, BCRYPT_SHA256_ALGORITHM,
            MS_KEY_STORAGE_PROVIDER, NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_PAD_PSS_FLAG,
            NCRYPT_PROV_HANDLE,
        };
        use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32};

        use super::Metadata;

        /// WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR
        pub const REQUEST_TYPE_CTAP2_CBOR: i32 = 1;
        /// PLUGIN_LOCK_STATUS
        pub const PLUGIN_LOCKED: i32 = 0;
        pub const PLUGIN_UNLOCKED: i32 = 1;
        /// AUTHENTICATOR_STATE
        pub const AUTHENTICATOR_STATE_ENABLED: i32 = 1;

        // pluginauthenticator.h

        #[repr(C)]
        pub struct OperationRequest {
            pub hwnd: *mut c_void,
            pub transaction_id: GUID,
            pub cb_request_signature: u32,
            pub pb_request_signature: *const u8,
            pub request_type: i32,
            pub cb_encoded_request: u32,
            pub pb_encoded_request: *const u8,
        }

        #[repr(C)]
        pub struct OperationResponse {
            pub cb_encoded_response: u32,
            /// CoTaskMemAlloc'ed: COM frees it after sending it to Windows.
            pub pb_encoded_response: *mut u8,
        }

        #[repr(C)]
        pub struct CancelOperationRequest {
            pub transaction_id: GUID,
            pub cb_request_signature: u32,
            pub pb_request_signature: *const u8,
        }

        // webauthn.h

        #[repr(C)]
        pub struct RpEntityInformation {
            pub dw_version: u32,
            pub pwsz_id: *const u16,
            pub pwsz_name: *const u16,
            pub pwsz_icon: *const u16,
        }

        #[repr(C)]
        pub struct UserEntityInformation {
            pub dw_version: u32,
            pub cb_id: u32,
            pub pb_id: *mut u8,
            pub pwsz_name: *const u16,
            pub pwsz_icon: *const u16,
            pub pwsz_display_name: *const u16,
        }

        #[repr(C)]
        pub struct CoseCredentialParameter {
            pub dw_version: u32,
            pub pwsz_credential_type: *const u16,
            pub l_alg: i32,
        }

        #[repr(C)]
        pub struct CoseCredentialParameters {
            pub c_credential_parameters: u32,
            pub p_credential_parameters: *mut CoseCredentialParameter,
        }

        #[repr(C)]
        pub struct Credential {
            pub dw_version: u32,
            pub cb_id: u32,
            pub pb_id: *mut u8,
            pub pwsz_credential_type: *const u16,
        }

        #[repr(C)]
        pub struct CredentialEx {
            pub dw_version: u32,
            pub cb_id: u32,
            pub pb_id: *mut u8,
            pub pwsz_credential_type: *const u16,
            pub dw_transports: u32,
        }

        #[repr(C)]
        pub struct CredentialList {
            pub c_credentials: u32,
            pub pp_credentials: *mut *mut CredentialEx,
        }

        #[repr(C)]
        pub struct Extensions {
            pub c_extensions: u32,
            pub p_extensions: *mut c_void,
        }

        /// WEBAUTHN_CREDENTIAL_ATTESTATION, version 8.
        #[repr(C)]
        pub struct CredentialAttestation {
            pub dw_version: u32,
            pub pwsz_format_type: *const u16,
            pub cb_authenticator_data: u32,
            pub pb_authenticator_data: *mut u8,
            pub cb_attestation: u32,
            pub pb_attestation: *mut u8,
            pub dw_attestation_decode_type: u32,
            pub pv_attestation_decode: *mut c_void,
            pub cb_attestation_object: u32,
            pub pb_attestation_object: *mut u8,
            pub cb_credential_id: u32,
            pub pb_credential_id: *mut u8,
            // version 2
            pub extensions: Extensions,
            // version 3
            pub dw_used_transport: u32,
            // version 4
            pub b_ep_att: i32,
            pub b_large_blob_supported: i32,
            pub b_resident_key: i32,
            // version 5
            pub b_prf_enabled: i32,
            // version 6
            pub cb_unsigned_extension_outputs: u32,
            pub pb_unsigned_extension_outputs: *mut u8,
            // version 7
            pub p_hmac_secret: *mut c_void,
            pub b_third_party_payment: i32,
            // version 8
            pub dw_transports: u32,
            pub cb_client_data_json: u32,
            pub pb_client_data_json: *mut u8,
            pub cb_registration_response_json: u32,
            pub pb_registration_response_json: *mut u8,
        }
        pub const CREDENTIAL_ATTESTATION_VERSION_8: u32 = 8;

        /// WEBAUTHN_ASSERTION, version 6: the version webauthn.dll's
        /// encoder was built with, as it is embedded (not pointed to) in
        /// WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE.
        #[repr(C)]
        pub struct Assertion {
            pub dw_version: u32,
            pub cb_authenticator_data: u32,
            pub pb_authenticator_data: *mut u8,
            pub cb_signature: u32,
            pub pb_signature: *mut u8,
            pub credential: Credential,
            pub cb_user_id: u32,
            pub pb_user_id: *mut u8,
            // version 2
            pub extensions: Extensions,
            pub cb_cred_large_blob: u32,
            pub pb_cred_large_blob: *mut u8,
            pub dw_cred_large_blob_status: u32,
            // version 3
            pub p_hmac_secret: *mut c_void,
            // version 4
            pub dw_used_transport: u32,
            // version 5
            pub cb_unsigned_extension_outputs: u32,
            pub pb_unsigned_extension_outputs: *mut u8,
            // version 6
            pub cb_client_data_json: u32,
            pub pb_client_data_json: *mut u8,
            pub cb_authentication_response_json: u32,
            pub pb_authentication_response_json: *mut u8,
        }
        pub const ASSERTION_VERSION_6: u32 = 6;

        // webauthnplugin.h

        #[repr(C)]
        pub struct AddAuthenticatorOptions {
            pub pwsz_authenticator_name: *const u16,
            /// REFCLSID: a pointer to the CLSID.
            pub rclsid: *const GUID,
            pub pwsz_plugin_rp_id: *const u16,
            /// Base64 of an SVG 1.1 image.
            pub pwsz_light_theme_logo_svg: *const u16,
            pub pwsz_dark_theme_logo_svg: *const u16,
            pub cb_authenticator_info: u32,
            pub pb_authenticator_info: *const u8,
            pub c_supported_rp_ids: u32,
            pub ppwsz_supported_rp_ids: *const *const u16,
        }

        #[repr(C)]
        pub struct AddAuthenticatorResponse {
            pub cb_op_sign_pub_key: u32,
            pub pb_op_sign_pub_key: *mut u8,
        }

        #[repr(C)]
        pub struct PluginCredentialDetails {
            pub cb_credential_id: u32,
            pub pb_credential_id: *const u8,
            pub pwsz_rp_id: *const u16,
            pub pwsz_rp_name: *const u16,
            pub cb_user_id: u32,
            pub pb_user_id: *const u8,
            pub pwsz_user_name: *const u16,
            pub pwsz_user_display_name: *const u16,
        }

        #[repr(C)]
        pub struct UserVerificationRequest {
            pub hwnd: *mut c_void,
            /// REFGUID: a pointer to the transaction id.
            pub rguid_transaction_id: *const GUID,
            pub pwsz_username: *const u16,
            pub pwsz_display_hint: *const u16,
        }

        #[repr(C)]
        pub struct CtapAuthenticatorOptions {
            pub dw_version: u32,
            pub l_up: i32,
            pub l_uv: i32,
            pub l_require_resident_key: i32,
        }

        #[repr(C)]
        pub struct CtapMakeCredentialRequest {
            pub dw_version: u32,
            /// The relying party ID as UTF-8, the bytes that are hashed.
            pub cb_rp_id: u32,
            pub pb_rp_id: *mut u8,
            pub cb_client_data_hash: u32,
            pub pb_client_data_hash: *mut u8,
            pub p_rp_information: *const RpEntityInformation,
            pub p_user_information: *const UserEntityInformation,
            pub web_authn_credential_parameters: CoseCredentialParameters,
            pub credential_list: CredentialList,
            pub cb_cbor_extensions_map: u32,
            pub pb_cbor_extensions_map: *mut u8,
            pub p_authenticator_options: *mut CtapAuthenticatorOptions,
            pub f_empty_pin_auth: i32,
            pub cb_pin_auth: u32,
            pub pb_pin_auth: *mut u8,
            pub l_hmac_secret_ext: i32,
            pub p_hmac_secret_mc_extension: *mut c_void,
            pub l_prf_ext: i32,
            pub cb_hmac_secret_salt_values: u32,
            pub pb_hmac_secret_salt_values: *mut u8,
            pub dw_cred_protect: u32,
            pub dw_pin_protocol: u32,
            pub dw_enterprise_attestation: u32,
            pub cb_cred_blob_ext: u32,
            pub pb_cred_blob_ext: *mut u8,
            pub l_large_blob_key_ext: i32,
            pub dw_large_blob_support: u32,
            pub l_min_pin_length_ext: i32,
            pub cb_json_ext: u32,
            pub pb_json_ext: *mut u8,
        }

        #[repr(C)]
        pub struct CtapGetAssertionRequest {
            pub dw_version: u32,
            pub pwsz_rp_id: *const u16,
            /// The relying party ID as UTF-8, the bytes that are hashed.
            pub cb_rp_id: u32,
            pub pb_rp_id: *mut u8,
            pub cb_client_data_hash: u32,
            pub pb_client_data_hash: *mut u8,
            pub credential_list: CredentialList,
            pub cb_cbor_extensions_map: u32,
            pub pb_cbor_extensions_map: *mut u8,
            pub p_authenticator_options: *mut CtapAuthenticatorOptions,
            pub f_empty_pin_auth: i32,
            pub cb_pin_auth: u32,
            pub pb_pin_auth: *mut u8,
            pub p_hmac_salt_extension: *mut c_void,
            pub cb_hmac_secret_salt_values: u32,
            pub pb_hmac_secret_salt_values: *mut u8,
            pub dw_pin_protocol: u32,
            pub l_cred_blob_ext: i32,
            pub l_large_blob_key_ext: i32,
            pub dw_cred_large_blob_operation: u32,
            pub cb_cred_large_blob_compressed: u32,
            pub pb_cred_large_blob_compressed: *mut u8,
            pub dw_cred_large_blob_original_size: u32,
            pub cb_json_ext: u32,
            pub pb_json_ext: *mut u8,
        }

        #[repr(C)]
        pub struct CtapGetAssertionResponse {
            pub web_authn_assertion: Assertion,
            pub p_user_information: *const UserEntityInformation,
            pub dw_number_of_credentials: u32,
            pub l_user_selected: i32,
            pub cb_large_blob_key: u32,
            pub pb_large_blob_key: *mut u8,
            pub cb_unsigned_extension_outputs: u32,
            pub pb_unsigned_extension_outputs: *mut u8,
        }

        type GetState = unsafe extern "system" fn(*const GUID, *mut i32) -> HRESULT;
        type Add =
            unsafe extern "system" fn(*const AddAuthenticatorOptions, *mut *mut AddAuthenticatorResponse) -> HRESULT;
        type FreeAdd = unsafe extern "system" fn(*mut AddAuthenticatorResponse);
        type Remove = unsafe extern "system" fn(*const GUID) -> HRESULT;
        type AddCredentials = unsafe extern "system" fn(*const GUID, u32, *const PluginCredentialDetails) -> HRESULT;
        type RemoveAllCredentials = unsafe extern "system" fn(*const GUID) -> HRESULT;
        type PerformUv = unsafe extern "system" fn(*const UserVerificationRequest, *mut u32, *mut *mut u8) -> HRESULT;
        type FreeBuffer = unsafe extern "system" fn(*mut u8);
        type SigningKey = unsafe extern "system" fn(*const GUID, *mut u32, *mut *mut u8) -> HRESULT;
        type DecodeMake = unsafe extern "system" fn(u32, *const u8, *mut *mut CtapMakeCredentialRequest) -> HRESULT;
        type FreeMake = unsafe extern "system" fn(*mut CtapMakeCredentialRequest);
        type DecodeGet = unsafe extern "system" fn(u32, *const u8, *mut *mut CtapGetAssertionRequest) -> HRESULT;
        type FreeGet = unsafe extern "system" fn(*mut CtapGetAssertionRequest);
        type EncodeMake = unsafe extern "system" fn(*const CredentialAttestation, *mut u32, *mut *mut u8) -> HRESULT;
        type EncodeGet = unsafe extern "system" fn(*const CtapGetAssertionResponse, *mut u32, *mut *mut u8) -> HRESULT;

        pub struct Api {
            pub get_state: GetState,
            add: Add,
            free_add: FreeAdd,
            pub remove: Remove,
            add_credentials: AddCredentials,
            pub remove_all_credentials: RemoveAllCredentials,
            perform_uv: PerformUv,
            free_uv: FreeBuffer,
            signing_key: SigningKey,
            free_key: FreeBuffer,
            decode_make: DecodeMake,
            free_make: FreeMake,
            decode_get: DecodeGet,
            free_get: FreeGet,
            encode_make: EncodeMake,
            encode_get: EncodeGet,
        }

        /// The API, if this Windows has all of it.
        pub fn api() -> Option<&'static Api> {
            static API: OnceLock<Option<Api>> = OnceLock::new();
            API.get_or_init(|| unsafe { load() }).as_ref()
        }

        unsafe fn load() -> Option<Api> {
            // From System32 only, never from the program's folder.
            let module = unsafe { LoadLibraryExW(w!("webauthn.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32) }.ok()?;
            macro_rules! function {
                ($name:literal as $type:ty) => {
                    unsafe {
                        std::mem::transmute::<unsafe extern "system" fn() -> isize, $type>(GetProcAddress(
                            module,
                            s!($name),
                        )?)
                    }
                };
            }
            Some(Api {
                get_state: function!("WebAuthNPluginGetAuthenticatorState" as GetState),
                add: function!("WebAuthNPluginAddAuthenticator" as Add),
                free_add: function!("WebAuthNPluginFreeAddAuthenticatorResponse" as FreeAdd),
                remove: function!("WebAuthNPluginRemoveAuthenticator" as Remove),
                add_credentials: function!("WebAuthNPluginAuthenticatorAddCredentials" as AddCredentials),
                remove_all_credentials: function!(
                    "WebAuthNPluginAuthenticatorRemoveAllCredentials" as RemoveAllCredentials
                ),
                perform_uv: function!("WebAuthNPluginPerformUserVerification" as PerformUv),
                free_uv: function!("WebAuthNPluginFreeUserVerificationResponse" as FreeBuffer),
                signing_key: function!("WebAuthNPluginGetOperationSigningPublicKey" as SigningKey),
                free_key: function!("WebAuthNPluginFreePublicKeyResponse" as FreeBuffer),
                decode_make: function!("WebAuthNDecodeMakeCredentialRequest" as DecodeMake),
                free_make: function!("WebAuthNFreeDecodedMakeCredentialRequest" as FreeMake),
                decode_get: function!("WebAuthNDecodeGetAssertionRequest" as DecodeGet),
                free_get: function!("WebAuthNFreeDecodedGetAssertionRequest" as FreeGet),
                encode_make: function!("WebAuthNEncodeMakeCredentialResponse" as EncodeMake),
                encode_get: function!("WebAuthNEncodeGetAssertionResponse" as EncodeGet),
            })
        }

        /// A buffer from Windows; empty for a null pointer.
        pub unsafe fn bytes<'a>(data: *const u8, length: u32) -> &'a [u8] {
            if data.is_null() || length == 0 {
                &[]
            } else {
                unsafe { std::slice::from_raw_parts(data, length as usize) }
            }
        }

        /// A NUL-terminated UTF-16 string from Windows; empty for null.
        unsafe fn text(data: *const u16) -> String {
            if data.is_null() {
                return String::new();
            }
            let mut length = 0;
            // Windows' strings are short; this stops a runaway read.
            while length < 4096 && unsafe { *data.add(length) } != 0 {
                length += 1;
            }
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(data, length) })
        }

        fn wide(text: &str) -> Vec<u16> {
            text.encode_utf16().chain([0]).collect()
        }

        /// The credential ids in a list from Windows.
        unsafe fn credential_ids(list: &CredentialList) -> Vec<Vec<u8>> {
            if list.pp_credentials.is_null() {
                return Vec::new();
            }
            (0..list.c_credentials as usize)
                .filter_map(|i| unsafe { (*list.pp_credentials.add(i)).as_ref() })
                .map(|c| unsafe { bytes(c.pb_id, c.cb_id) }.to_vec())
                .filter(|id| !id.is_empty())
                .collect()
        }

        /// Frees what Windows decoded when it goes out of scope.
        struct Decoded<T>(*mut T, unsafe extern "system" fn(*mut T));

        impl<T> Drop for Decoded<T> {
            fn drop(&mut self) {
                unsafe { (self.1)(self.0) };
            }
        }

        fn utf8(data: &[u8]) -> Result<String, HRESULT> {
            String::from_utf8(data.to_vec()).map_err(|_| E_INVALIDARG)
        }

        pub unsafe fn decode_creation(api: &Api, encoded: &[u8]) -> Result<SystemRequest, HRESULT> {
            let mut decoded = null_mut();
            let hr = unsafe { (api.decode_make)(encoded.len() as u32, encoded.as_ptr(), &mut decoded) };
            if hr.is_err() {
                return Err(hr);
            }
            if decoded.is_null() {
                return Err(E_UNEXPECTED);
            }
            let decoded = Decoded(decoded, api.free_make);
            let r = unsafe { &*decoded.0 };
            let user = unsafe { r.p_user_information.as_ref() }.ok_or(E_INVALIDARG)?;
            let rp_name =
                unsafe { r.p_rp_information.as_ref() }.map(|rp| unsafe { text(rp.pwsz_name) }).unwrap_or_default();
            let parameters = &r.web_authn_credential_parameters;
            let algorithms = if parameters.p_credential_parameters.is_null() {
                Vec::new()
            } else {
                (0..parameters.c_credential_parameters as usize)
                    .map(|i| unsafe { &*parameters.p_credential_parameters.add(i) })
                    .filter(|p| {
                        let kind = unsafe { text(p.pwsz_credential_type) };
                        kind.is_empty() || kind == "public-key"
                    })
                    .map(|p| p.l_alg as i64)
                    .collect()
            };
            Ok(SystemRequest::Create(SystemCreation {
                rp_id: utf8(unsafe { bytes(r.pb_rp_id, r.cb_rp_id) })?,
                rp_name,
                user_handle: unsafe { bytes(user.pb_id, user.cb_id) }.to_vec(),
                user_name: unsafe { text(user.pwsz_name) },
                user_display_name: unsafe { text(user.pwsz_display_name) },
                client_data_hash: unsafe { bytes(r.pb_client_data_hash, r.cb_client_data_hash) }.to_vec(),
                algorithms,
                exclude_credentials: unsafe { credential_ids(&r.credential_list) },
            }))
        }

        pub unsafe fn decode_sign_in(api: &Api, encoded: &[u8]) -> Result<SystemRequest, HRESULT> {
            let mut decoded = null_mut();
            let hr = unsafe { (api.decode_get)(encoded.len() as u32, encoded.as_ptr(), &mut decoded) };
            if hr.is_err() {
                return Err(hr);
            }
            if decoded.is_null() {
                return Err(E_UNEXPECTED);
            }
            let decoded = Decoded(decoded, api.free_get);
            let r = unsafe { &*decoded.0 };
            Ok(SystemRequest::SignIn(SystemSignIn {
                rp_id: utf8(unsafe { bytes(r.pb_rp_id, r.cb_rp_id) })?,
                client_data_hash: unsafe { bytes(r.pb_client_data_hash, r.cb_client_data_hash) }.to_vec(),
                allow_credentials: unsafe { credential_ids(&r.credential_list) },
            }))
        }

        /// Hand Windows' encoding of the answer to COM, which frees it.
        unsafe fn respond(response: *mut OperationResponse, length: u32, data: *mut u8) -> HRESULT {
            if data.is_null() {
                return E_UNEXPECTED;
            }
            unsafe { response.write(OperationResponse { cb_encoded_response: length, pb_encoded_response: data }) };
            S_OK
        }

        pub unsafe fn encode_created(api: &Api, auth_data: &[u8], response: *mut OperationResponse) -> HRESULT {
            // "none" attestation; the rest stays zero, as in Microsoft's sample.
            let mut attestation: CredentialAttestation = unsafe { std::mem::zeroed() };
            attestation.dw_version = CREDENTIAL_ATTESTATION_VERSION_8;
            attestation.pwsz_format_type = w!("none").as_ptr();
            attestation.cb_authenticator_data = auth_data.len() as u32;
            attestation.pb_authenticator_data = auth_data.as_ptr() as *mut u8;
            let (mut length, mut data) = (0u32, null_mut());
            let hr = unsafe { (api.encode_make)(&attestation, &mut length, &mut data) };
            if hr.is_err() {
                return hr;
            }
            unsafe { respond(response, length, data) }
        }

        pub unsafe fn encode_signed(
            api: &Api,
            assertion: &SystemAssertion,
            response: *mut OperationResponse,
        ) -> HRESULT {
            let user = UserEntityInformation {
                dw_version: 1,
                cb_id: assertion.user_handle.len() as u32,
                pb_id: assertion.user_handle.as_ptr() as *mut u8,
                pwsz_name: null(),
                pwsz_icon: null(),
                pwsz_display_name: null(),
            };
            let mut answer: CtapGetAssertionResponse = unsafe { std::mem::zeroed() };
            let a = &mut answer.web_authn_assertion;
            a.dw_version = ASSERTION_VERSION_6;
            a.cb_authenticator_data = assertion.authenticator_data.len() as u32;
            a.pb_authenticator_data = assertion.authenticator_data.as_ptr() as *mut u8;
            a.cb_signature = assertion.signature.len() as u32;
            a.pb_signature = assertion.signature.as_ptr() as *mut u8;
            a.credential = Credential {
                dw_version: 1,
                cb_id: assertion.credential_id.len() as u32,
                pb_id: assertion.credential_id.as_ptr() as *mut u8,
                pwsz_credential_type: w!("public-key").as_ptr(),
            };
            a.cb_user_id = assertion.user_handle.len() as u32;
            a.pb_user_id = assertion.user_handle.as_ptr() as *mut u8;
            answer.p_user_information = &user;
            answer.dw_number_of_credentials = 1;
            let (mut length, mut data) = (0u32, null_mut());
            let hr = unsafe { (api.encode_get)(&answer, &mut length, &mut data) };
            if hr.is_err() {
                return hr;
            }
            unsafe { respond(response, length, data) }
        }

        /// Check Windows' signature over the request: SHA-256 of the
        /// encoded request, with the key Windows gave this provider.
        pub unsafe fn verify_request(api: &Api, encoded: &[u8], signature: &[u8]) -> Result<(), String> {
            if signature.is_empty() {
                return Err("no signature".into());
            }
            let (mut length, mut key) = (0u32, null_mut());
            let hr = unsafe { (api.signing_key)(&super::CLSID, &mut length, &mut key) };
            if hr.is_err() || key.is_null() {
                return Err(format!("no signing key: {}", super::hresult_text(hr)));
            }
            let blob = unsafe { bytes(key, length) }.to_vec();
            unsafe { (api.free_key)(key) };
            if blob.len() < 8 {
                return Err("damaged signing key".into());
            }
            let hash = twosecret_core::crypto::sha256(encoded);
            let mut provider = NCRYPT_PROV_HANDLE(0);
            unsafe { NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0) }
                .map_err(|e| e.to_string())?;
            let mut handle = NCRYPT_KEY_HANDLE(0);
            let result = unsafe {
                NCryptImportKey(provider, None, BCRYPT_PUBLIC_KEY_BLOB, None, &mut handle, &blob, NCRYPT_FLAGS(0))
            }
            .and_then(|()| {
                // BCRYPT_KEY_BLOB starts with its Magic; Windows has used
                // RSA (signed with PSS) and ECDSA keys.
                let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
                if magic == BCRYPT_RSAPUBLIC_MAGIC.0 {
                    let padding = BCRYPT_PSS_PADDING_INFO { pszAlgId: BCRYPT_SHA256_ALGORITHM, cbSalt: 32 };
                    let padding = std::ptr::from_ref(&padding).cast::<c_void>();
                    unsafe { NCryptVerifySignature(handle, Some(padding), &hash, signature, NCRYPT_PAD_PSS_FLAG) }
                } else {
                    unsafe { NCryptVerifySignature(handle, None, &hash, signature, NCRYPT_FLAGS(0)) }
                }
            });
            if handle.0 != 0 {
                let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(handle.0)) };
            }
            let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(provider.0)) };
            result.map_err(|e| e.to_string())
        }

        /// Windows Hello for the request with this transaction id.
        pub unsafe fn verify_user(
            api: &Api,
            hwnd: isize,
            transaction_id: &GUID,
            user_name: &str,
            hint: &str,
        ) -> Result<(), HRESULT> {
            let (user_name, hint) = (wide(user_name), wide(hint));
            let request = UserVerificationRequest {
                hwnd: hwnd as *mut c_void,
                rguid_transaction_id: transaction_id,
                pwsz_username: user_name.as_ptr(),
                pwsz_display_hint: hint.as_ptr(),
            };
            let (mut length, mut signature) = (0u32, null_mut());
            let hr = unsafe { (api.perform_uv)(&request, &mut length, &mut signature) };
            if !signature.is_null() {
                unsafe { (api.free_uv)(signature) };
            }
            if hr.is_err() {
                Err(hr)
            } else {
                Ok(())
            }
        }

        pub unsafe fn add_authenticator(api: &Api) -> Result<(), HRESULT> {
            let name = wide("2Secret");
            let rp_id = wide("2secret.app");
            let logo = wide(&twosecret_core::util::b64(include_bytes!("../assets/icon.svg")));
            let info = twosecret_core::passkey::authenticator_info();
            let options = AddAuthenticatorOptions {
                pwsz_authenticator_name: name.as_ptr(),
                rclsid: &super::CLSID,
                pwsz_plugin_rp_id: rp_id.as_ptr(),
                pwsz_light_theme_logo_svg: logo.as_ptr(),
                pwsz_dark_theme_logo_svg: logo.as_ptr(),
                cb_authenticator_info: info.len() as u32,
                pb_authenticator_info: info.as_ptr(),
                // Every website.
                c_supported_rp_ids: 0,
                ppwsz_supported_rp_ids: null(),
            };
            let mut response = null_mut();
            let hr = unsafe { (api.add)(&options, &mut response) };
            // The request signing key is asked for with each request instead.
            if !response.is_null() {
                unsafe { (api.free_add)(response) };
            }
            if hr.is_ok() || hr == NTE_EXISTS {
                Ok(())
            } else {
                Err(hr)
            }
        }

        /// Replace Windows' list of 2Secret's passkeys.
        pub unsafe fn replace_credentials(api: &Api, list: &[Metadata]) -> Result<(), HRESULT> {
            // Fails when the list is empty already; adding then tells.
            let _ = unsafe { (api.remove_all_credentials)(&super::CLSID) };
            if list.is_empty() {
                return Ok(());
            }
            let texts: Vec<[Vec<u16>; 4]> = list
                .iter()
                .map(|m| [wide(&m.rp_id), wide(&m.rp_name), wide(&m.user_name), wide(&m.user_display_name)])
                .collect();
            let details: Vec<PluginCredentialDetails> = list
                .iter()
                .zip(&texts)
                .map(|(m, [rp_id, rp_name, user_name, display_name])| PluginCredentialDetails {
                    cb_credential_id: m.credential_id.len() as u32,
                    pb_credential_id: m.credential_id.as_ptr(),
                    pwsz_rp_id: rp_id.as_ptr(),
                    pwsz_rp_name: rp_name.as_ptr(),
                    cb_user_id: m.user_id.len() as u32,
                    pb_user_id: m.user_id.as_ptr(),
                    pwsz_user_name: user_name.as_ptr(),
                    pwsz_user_display_name: display_name.as_ptr(),
                })
                .collect();
            let hr = unsafe { (api.add_credentials)(&super::CLSID, details.len() as u32, details.as_ptr()) };
            if hr.is_err() {
                Err(hr)
            } else {
                Ok(())
            }
        }

        // The layouts of x64 and ARM64 Windows, worked out from the headers
        // by C's rules (pointers and alignment 8, DWORD/LONG/BOOL 4, GUID 16
        // with alignment 4).
        #[cfg(target_pointer_width = "64")]
        const _: () = {
            use std::mem::{offset_of, size_of};
            assert!(size_of::<OperationRequest>() == 56);
            assert!(offset_of!(OperationRequest, transaction_id) == 8);
            assert!(offset_of!(OperationRequest, cb_request_signature) == 24);
            assert!(offset_of!(OperationRequest, pb_request_signature) == 32);
            assert!(offset_of!(OperationRequest, request_type) == 40);
            assert!(offset_of!(OperationRequest, cb_encoded_request) == 44);
            assert!(offset_of!(OperationRequest, pb_encoded_request) == 48);
            assert!(size_of::<OperationResponse>() == 16);
            assert!(size_of::<CancelOperationRequest>() == 32);
            assert!(offset_of!(CancelOperationRequest, pb_request_signature) == 24);
            assert!(size_of::<UserEntityInformation>() == 40);
            assert!(size_of::<CredentialEx>() == 32);
            assert!(size_of::<CredentialAttestation>() == 192);
            assert!(offset_of!(CredentialAttestation, extensions) == 96);
            assert!(offset_of!(CredentialAttestation, b_prf_enabled) == 128);
            assert!(offset_of!(CredentialAttestation, p_hmac_secret) == 144);
            assert!(offset_of!(CredentialAttestation, pb_registration_response_json) == 184);
            assert!(size_of::<Assertion>() == 168);
            assert!(offset_of!(Assertion, credential) == 32);
            assert!(offset_of!(Assertion, cb_user_id) == 56);
            assert!(offset_of!(Assertion, p_hmac_secret) == 112);
            assert!(offset_of!(Assertion, dw_used_transport) == 120);
            assert!(offset_of!(Assertion, cb_unsigned_extension_outputs) == 124);
            assert!(offset_of!(Assertion, pb_authentication_response_json) == 160);
            assert!(size_of::<CtapGetAssertionResponse>() == 216);
            assert!(offset_of!(CtapGetAssertionResponse, p_user_information) == 168);
            assert!(offset_of!(CtapGetAssertionResponse, dw_number_of_credentials) == 176);
            assert!(size_of::<AddAuthenticatorOptions>() == 72);
            assert!(offset_of!(AddAuthenticatorOptions, cb_authenticator_info) == 40);
            assert!(offset_of!(AddAuthenticatorOptions, c_supported_rp_ids) == 56);
            assert!(size_of::<PluginCredentialDetails>() == 64);
            assert!(offset_of!(PluginCredentialDetails, cb_user_id) == 32);
            assert!(size_of::<UserVerificationRequest>() == 32);
            assert!(offset_of!(CtapMakeCredentialRequest, pb_client_data_hash) == 24);
            assert!(offset_of!(CtapMakeCredentialRequest, p_rp_information) == 32);
            assert!(offset_of!(CtapMakeCredentialRequest, p_user_information) == 40);
            assert!(offset_of!(CtapMakeCredentialRequest, web_authn_credential_parameters) == 48);
            assert!(offset_of!(CtapMakeCredentialRequest, credential_list) == 64);
            assert!(offset_of!(CtapMakeCredentialRequest, p_authenticator_options) == 96);
            assert!(offset_of!(CtapGetAssertionRequest, cb_rp_id) == 16);
            assert!(offset_of!(CtapGetAssertionRequest, pb_client_data_hash) == 40);
            assert!(offset_of!(CtapGetAssertionRequest, credential_list) == 48);
            assert!(offset_of!(CtapGetAssertionRequest, p_authenticator_options) == 80);
        };
    }
}

#[cfg(not(all(windows, feature = "desktop")))]
mod imp {
    use super::{Outcome, Unverified};

    pub fn start() {}
    pub fn use_windows_passkeys() {}
    pub fn answer(_rid: &str, _outcome: Outcome) {}
    pub fn forget() {}
    pub async fn verify_user(_rid: &str, _user_name: &str, _hint: &str) -> Result<(), Unverified> {
        Ok(())
    }
}

/// `file:///C:/Users/...` for a Windows path: what the package manager
/// takes, with the bytes a URI cannot hold percent-encoded.
#[cfg_attr(not(all(windows, feature = "desktop")), allow(dead_code))]
fn file_uri(path: &str) -> String {
    let mut uri = String::from("file:///");
    for byte in path.replace('\\', "/").bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/:".contains(&byte) {
            uri.push(byte as char);
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_uris_for_the_package_manager() {
        assert_eq!(
            file_uri(r"C:\Users\Jan de Vries\AppData\Local\Programs\2Secret"),
            "file:///C:/Users/Jan%20de%20Vries/AppData/Local/Programs/2Secret"
        );
        assert_eq!(file_uri(r"C:\Users\José\a#b"), "file:///C:/Users/Jos%C3%A9/a%23b");
    }
}
