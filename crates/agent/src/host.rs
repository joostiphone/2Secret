//! The native messaging host: the program a browser starts for the 2Secret
//! extension. It speaks the browser's framing on stdin and stdout (4 bytes
//! little-endian length, then UTF-8 JSON) and connects to the running app as
//! a browser (`role: browser`), then waits for logins the user allowed an
//! agent to fill (`browser.wait`), hands each to the extension and reports
//! how it went (`browser.result`).
//!
//! The host never reads the vault: the app only gives it the one login the
//! user just allowed. It leaves when the browser closes the port (stdin
//! EOF), when the app goes away (socket EOF), when the app cannot be reached
//! for [`CONNECT_TRIES`] tries, or when `exit_marker` appears (an update is
//! being installed on Windows and needs the program file free).
//!
//! Frames from the extension: `{"type":"hello","extension":"1.11.0",
//! "browser":"chrome"}` and `{"type":"fill_result","id":…,"outcome":
//! "filled"|"nothing"|"no_tab","submitted":true}`. Frames to the extension:
//! `{"type":"status","app":true|false,"version":…}`, `{"type":"ping"}` every
//! [`PING_EVERY`] (it keeps the extension's service worker alive), and
//! `{"type":"fill", …the login…}`.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use twosecret_core::agent::{
    browser_label, browser_name, FillCommand, FillOutcome, FillOutcomeParams, HelloParams, Role, WaitResult, PROTOCOL,
};
use zeroize::Zeroizing;

use crate::client::{AppClient, ClientError};
use crate::key::AgentKey;
pub use crate::native_host::{GECKO_ID, HOST_NAME};

/// Longest frame in either direction (the browser accepts 1 MB from a host).
pub const MAX_FRAME: usize = 1024 * 1024;
/// How often the host tries to reach the app before giving up.
pub const CONNECT_TRIES: u32 = 10;
pub const CONNECT_PAUSE: Duration = Duration::from_secs(2);
/// A ping every 20 s keeps the extension's service worker (idle limit 30 s) alive.
pub const PING_EVERY: Duration = Duration::from_secs(20);
/// How long the host waits for the extension to report a fill.
pub const FILL_WAIT: Duration = Duration::from_secs(20);
/// How long the host waits for the extension's `hello` (which names the
/// browser) before it introduces itself to the app.
pub const HELLO_WAIT: Duration = Duration::from_secs(2);

/// One frame from the browser, or `None` at a clean end of the stream.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too long"));
    }
    let mut buf = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// One frame to the browser.
pub fn write_frame(w: &mut impl Write, v: &Value) -> io::Result<()> {
    let text = Zeroizing::new(serde_json::to_vec(v)?);
    if text.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too long"));
    }
    w.write_all(&(text.len() as u32).to_le_bytes())?;
    w.write_all(&text)?;
    w.flush()
}

/// How to run the host.
pub struct HostOptions {
    /// The data directory (where the app listens and the key lives).
    pub home: PathBuf,
    /// The browser as far as the starter could tell (`chrome`, `firefox`,
    /// ...); what the extension says in its `hello` wins.
    pub browser: Option<String>,
    /// The extension's origin or id, from the arguments.
    pub extension: Option<String>,
    /// Leave at once when this file exists (an update is being installed).
    pub exit_marker: Option<PathBuf>,
    /// End the process the moment the browser closes the port, whatever the
    /// host is waiting for (the app answers a browser's `auth` only once the
    /// vault is unlocked, which may take hours). Off in tests.
    pub exit_when_gone: bool,
}

/// The outgoing side: one writer shared by the pinger and the main loop.
struct Out {
    writer: Mutex<Box<dyn Write + Send>>,
    stop: Arc<AtomicBool>,
}

impl Out {
    /// Send a frame; a failure means the browser is gone and stops everything.
    fn send(&self, v: &Value) -> bool {
        let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
        match write_frame(&mut *w, v) {
            Ok(()) => true,
            Err(_) => {
                self.stop.store(true, Ordering::SeqCst);
                false
            }
        }
    }
}

/// What the extension told us in `hello`.
#[derive(Default)]
struct Extension {
    browser: Option<String>,
    version: String,
    seen: bool,
}

fn marker_present(marker: Option<&Path>) -> bool {
    marker.is_some_and(Path::exists)
}

/// Sleep `total` in small steps, returning early (false) when stopping.
fn pause(total: Duration, stop: &AtomicBool, marker: Option<&Path>) -> bool {
    let end = Instant::now() + total;
    while Instant::now() < end {
        if stop.load(Ordering::SeqCst) || marker_present(marker) {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
    true
}

/// Run the host on `input` and `output` (the browser's pipes) until one side
/// goes away. Returns the process exit code.
pub fn run(input: impl Read + Send + 'static, output: impl Write + Send + 'static, opts: HostOptions) -> i32 {
    let stop = Arc::new(AtomicBool::new(false));
    let out = Arc::new(Out { writer: Mutex::new(Box::new(output)), stop: stop.clone() });
    let extension = Arc::new(Mutex::new(Extension::default()));
    let (results_tx, results_rx) = mpsc::channel::<FillOutcomeParams>();
    let exit_when_gone = opts.exit_when_gone;

    // Frames from the extension.
    {
        let stop = stop.clone();
        let extension = extension.clone();
        thread::spawn(move || {
            let mut input = input;
            loop {
                match read_frame(&mut input) {
                    Ok(Some(frame)) => {
                        let Ok(v) = serde_json::from_slice::<Value>(&frame) else { continue };
                        match v.get("type").and_then(Value::as_str) {
                            Some("hello") => {
                                let mut ext = extension.lock().unwrap_or_else(|e| e.into_inner());
                                ext.browser = v
                                    .get("browser")
                                    .and_then(Value::as_str)
                                    .map(browser_name)
                                    .filter(|b| !b.is_empty());
                                ext.version = v
                                    .get("extension")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .chars()
                                    .take(40)
                                    .collect();
                                ext.seen = true;
                            }
                            Some("fill_result") => {
                                if let Ok(p) = serde_json::from_value::<FillOutcomeParams>(v) {
                                    let _ = results_tx.send(p);
                                }
                            }
                            _ => {}
                        }
                    }
                    Ok(None) | Err(_) => {
                        stop.store(true, Ordering::SeqCst);
                        if exit_when_gone {
                            std::process::exit(0);
                        }
                        break;
                    }
                }
            }
        });
    }

    // Pings keep the extension's service worker alive and notice a closed port.
    {
        let out = out.clone();
        let stop = stop.clone();
        thread::spawn(move || {
            while pause(PING_EVERY, &stop, None) {
                if !out.send(&json!({ "type": "ping" })) {
                    break;
                }
            }
            if exit_when_gone {
                std::process::exit(0);
            }
        });
    }

    let marker = opts.exit_marker.as_deref();
    let started = Instant::now();
    while started.elapsed() < HELLO_WAIT && !extension.lock().unwrap_or_else(|e| e.into_inner()).seen {
        if stop.load(Ordering::SeqCst) {
            return 0;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let (browser, ext_version) = {
        let ext = extension.lock().unwrap_or_else(|e| e.into_inner());
        (ext.browser.clone().or(opts.browser).unwrap_or_else(|| "browser".to_string()), ext.version.clone())
    };

    let mut client = None;
    for attempt in 0..CONNECT_TRIES {
        if stop.load(Ordering::SeqCst) || marker_present(marker) {
            return 0;
        }
        // No read timeout: a browser's `auth` is answered once the vault is unlocked.
        match AppClient::connect_with_timeout(&opts.home, None) {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(_) if attempt + 1 < CONNECT_TRIES => {
                if !pause(CONNECT_PAUSE, &stop, marker) {
                    return 0;
                }
            }
            Err(_) => {}
        }
    }
    let Some(mut client) = client else {
        out.send(&json!({ "type": "status", "app": false }));
        return 0;
    };

    let key = match AgentKey::load_or_create(&opts.home, &format!("browser-{browser}")) {
        Ok(k) => k,
        Err(e) => {
            out.send(&json!({ "type": "status", "app": false, "error": format!("no key: {e}") }));
            return 1;
        }
    };
    let hello = HelloParams {
        protocol: PROTOCOL,
        name: format!("{} extension", browser_label(&browser)),
        version: ext_version,
        agent_key: key.public_key_b64(),
        parent: None,
        role: Role::Browser,
        browser: Some(browser.clone()),
        extension: opts.extension.clone(),
    };
    if let Err(e) = client.hello_auth_as(&key, &hello) {
        out.send(&json!({ "type": "status", "app": false, "error": e.to_string() }));
        return 1;
    }
    if !out.send(&json!({ "type": "status", "app": true, "version": client.app_version })) {
        return 0;
    }

    loop {
        if stop.load(Ordering::SeqCst) || marker_present(marker) {
            return 0;
        }
        let wait: WaitResult = match client.call("browser.wait", json!({})) {
            Ok(w) => w,
            Err(ClientError::Rpc(e)) => {
                out.send(&json!({ "type": "status", "app": false, "error": e.message }));
                return 1;
            }
            Err(_) => {
                out.send(&json!({ "type": "status", "app": false }));
                return 0;
            }
        };
        let Some(job) = wait.job else { continue };
        let id = job.id.clone();
        if !out.send(&fill_frame(&job)) {
            return 0;
        }
        drop(job);
        let deadline = Instant::now() + FILL_WAIT;
        let reported = loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || stop.load(Ordering::SeqCst) {
                break None;
            }
            match results_rx.recv_timeout(left.min(Duration::from_millis(250))) {
                Ok(r) if r.id == id => break Some(r),
                Ok(_) => continue,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break None,
            }
        };
        // No answer from the extension counts as "no tab": the app may try
        // another browser.
        let params = reported.unwrap_or(FillOutcomeParams { id, outcome: FillOutcome::NoTab, submitted: false });
        let params = serde_json::to_value(&params).unwrap_or(Value::Null);
        if client.call_value("browser.result", params).is_err() {
            out.send(&json!({ "type": "status", "app": false }));
            return 0;
        }
    }
}

/// The `fill` frame for a job.
fn fill_frame(job: &FillCommand) -> Value {
    let mut v = serde_json::to_value(job).unwrap_or(Value::Null);
    if let Some(o) = v.as_object_mut() {
        o.insert("type".into(), Value::String("fill".into()));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frames_round_trip_and_are_capped() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &json!({ "type": "ping" })).unwrap();
        assert_eq!(&buf[..4], &15u32.to_le_bytes());
        write_frame(&mut buf, &json!({ "type": "hello", "browser": "chrome" })).unwrap();
        let mut r = Cursor::new(buf);
        let first = read_frame(&mut r).unwrap().unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&first).unwrap()["type"], "ping");
        let second = read_frame(&mut r).unwrap().unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&second).unwrap()["browser"], "chrome");
        assert!(read_frame(&mut r).unwrap().is_none(), "clean end");

        let mut truncated = Vec::new();
        truncated.extend_from_slice(&10u32.to_le_bytes());
        truncated.extend_from_slice(b"{\"a\"");
        assert!(read_frame(&mut Cursor::new(truncated)).is_err());
        let mut huge = Vec::new();
        huge.extend_from_slice(&((MAX_FRAME + 1) as u32).to_le_bytes());
        assert!(read_frame(&mut Cursor::new(huge)).is_err());
        let big = Value::String("x".repeat(MAX_FRAME));
        assert!(write_frame(&mut Vec::new(), &big).is_err());

        let job = FillCommand {
            id: "f-1".into(),
            url: "https://github.com/login".into(),
            rules: Vec::new(),
            username: "octo".into(),
            password: "hunter2".into(),
            code: String::new(),
            submit: true,
        };
        let frame = fill_frame(&job);
        assert_eq!(frame["type"], "fill");
        assert_eq!(frame["password"], "hunter2");
        assert_eq!(frame["submit"], true);
    }

    /// The whole host against a fake app on a Unix socket, with socket pairs
    /// as the browser's pipes.
    #[cfg(unix)]
    #[test]
    fn host_talks_to_the_app_and_the_extension() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::{UnixListener, UnixStream};

        let home = std::env::temp_dir().join(format!("2secret-host-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let listener = UnixListener::bind(crate::client::socket_path(&home)).unwrap();
        let app = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            let mut seen: Vec<Value> = Vec::new();
            let mut waits = 0;
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                let msg: Value = serde_json::from_str(&line).unwrap();
                seen.push(msg.clone());
                let id = msg["id"].clone();
                let result = match msg["method"].as_str().unwrap() {
                    "hello" => {
                        json!({ "protocol": PROTOCOL, "app_version": "9.9", "nonce": twosecret_core::agent::new_nonce() })
                    }
                    "auth" => json!({ "agent_id": "AAAA-BBBB", "state": "paired" }),
                    "browser.wait" => {
                        waits += 1;
                        if waits == 1 {
                            json!({ "job": { "id": "f-7", "url": "https://github.com/login", "rules": [{"domain": "github.com", "https": true, "port": null, "exact": false}],
                                "username": "octo", "password": "hunter2", "code": "123456", "submit": true } })
                        } else {
                            thread::sleep(Duration::from_millis(400));
                            json!({ "job": null })
                        }
                    }
                    "browser.result" => json!({}),
                    other => panic!("unexpected {other}"),
                };
                let mut text = json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string();
                text.push('\n');
                writer.write_all(text.as_bytes()).unwrap();
            }
            seen
        });

        let (mut ext_writer, host_stdin) = UnixStream::pair().unwrap();
        let (host_stdout, mut ext_reader) = UnixStream::pair().unwrap();
        ext_reader.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let opts = HostOptions {
            home: home.clone(),
            browser: Some("edge".into()),
            extension: Some("chrome-extension://gnkfgnlegljjfnihdefkjepdoaphccfd/".into()),
            exit_marker: None,
            exit_when_gone: false,
        };
        let host = thread::spawn(move || run(host_stdin, host_stdout, opts));

        write_frame(&mut ext_writer, &json!({ "type": "hello", "extension": "1.11.0", "browser": "chrome" })).unwrap();
        let next = |r: &mut UnixStream| -> Value {
            loop {
                let frame = read_frame(r).unwrap().expect("a frame");
                let v: Value = serde_json::from_slice(&frame).unwrap();
                if v["type"] != "ping" {
                    return v;
                }
            }
        };
        let status = next(&mut ext_reader);
        assert_eq!(status["type"], "status");
        assert_eq!(status["app"], true);
        assert_eq!(status["version"], "9.9");
        let fill = next(&mut ext_reader);
        assert_eq!(fill["type"], "fill");
        assert_eq!(fill["id"], "f-7");
        assert_eq!(fill["password"], "hunter2");
        assert_eq!(fill["code"], "123456");
        assert_eq!(fill["rules"][0]["domain"], "github.com");
        write_frame(
            &mut ext_writer,
            &json!({ "type": "fill_result", "id": "f-7", "outcome": "filled", "submitted": true }),
        )
        .unwrap();
        // The browser closes the port: the host stops after its next wait.
        thread::sleep(Duration::from_millis(200));
        drop(ext_writer);
        assert_eq!(host.join().unwrap(), 0);
        let seen = app.join().unwrap();
        let hello = &seen[0];
        assert_eq!(hello["method"], "hello");
        assert_eq!(hello["params"]["role"], "browser");
        assert_eq!(hello["params"]["browser"], "chrome", "the extension's hello wins over the starter's guess");
        assert_eq!(hello["params"]["name"], "Chrome extension");
        assert_eq!(hello["params"]["version"], "1.11.0");
        assert_eq!(hello["params"]["extension"], "chrome-extension://gnkfgnlegljjfnihdefkjepdoaphccfd/");
        assert_eq!(seen[1]["method"], "auth");
        assert_eq!(seen[2]["method"], "browser.wait");
        assert_eq!(seen[3]["method"], "browser.result");
        assert_eq!(seen[3]["params"], json!({ "id": "f-7", "outcome": "filled", "submitted": true }));
        assert!(AgentKey::path(&home, "browser-chrome").is_file(), "one key per browser");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[cfg(unix)]
    #[test]
    fn host_gives_up_without_the_app() {
        use std::os::unix::net::UnixStream;
        let home = std::env::temp_dir().join(format!("2secret-nohost-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let marker = home.join("update-marker");
        std::fs::write(&marker, b"").unwrap();
        let (ext_writer, host_stdin) = UnixStream::pair().unwrap();
        let (host_stdout, _ext_reader) = UnixStream::pair().unwrap();
        let opts = HostOptions {
            home: home.clone(),
            browser: None,
            extension: None,
            exit_marker: Some(marker),
            exit_when_gone: false,
        };
        let started = Instant::now();
        // The marker is present: the host leaves without trying the socket.
        assert_eq!(run(host_stdin, host_stdout, opts), 0);
        assert!(started.elapsed() < CONNECT_PAUSE + HELLO_WAIT + Duration::from_secs(1));
        drop(ext_writer);
        let _ = std::fs::remove_dir_all(&home);
    }
}
