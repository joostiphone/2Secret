//! Filling a login through a Chromium's debugging port: the extension's
//! test page is served locally, a headless Chromium opens it, and `cdp::fill`
//! fills the user name and password into the right tab and submits, so the
//! page posts them back to the test server. Needs a Chromium: `CHROME` names
//! the binary (`chromium`, `google-chrome`, Playwright's download).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use twosecret_agent::cdp::{self, CdpError};
use twosecret_core::agent::{FillCommand, FillOutcome};
use twosecret_core::util::fill_rules;

const PAGE: &str = include_str!("../../../extension/tests/login.html");

/// A web server for one page: GET gives the sign-in page, POST /done
/// records the form.
fn serve_page() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let posts = Arc::new(Mutex::new(Vec::new()));
    let seen = posts.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let method = line.split_whitespace().next().unwrap_or_default().to_string();
            let mut length = 0usize;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                    break;
                }
                if let Some(v) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; length];
            if length > 0 {
                let _ = reader.read_exact(&mut body);
            }
            let (status, content) = if method == "POST" {
                seen.lock().unwrap().push(String::from_utf8_lossy(&body).into_owned());
                ("200 OK", "<html><body>done</body></html>".to_string())
            } else {
                ("200 OK", PAGE.to_string())
            };
            let mut stream = stream;
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{content}",
                content.len()
            );
        }
    });
    (port, posts)
}

struct Browser {
    child: std::process::Child,
    endpoint: String,
}

impl Drop for Browser {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A headless Chromium with its debugging port, opened at `url`.
fn start_browser(url: &str) -> Browser {
    let binary = std::env::var("CHROME").unwrap_or_else(|_| "chromium".to_string());
    let profile = std::env::temp_dir().join(format!("2secret-cdp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&profile);
    let mut child = Command::new(&binary)
        .args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--no-first-run",
            "--remote-debugging-port=0",
            &format!("--user-data-dir={}", profile.display()),
            url,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot start {binary}: {e} (set CHROME to a Chromium binary)"));
    // "DevTools listening on ws://127.0.0.1:PORT/devtools/browser/…"
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if let Some(rest) = line.trim().strip_prefix("DevTools listening on ws://") {
                let host_port = rest.split('/').next().unwrap_or_default().to_string();
                let _ = tx.send(host_port);
            }
        }
    });
    let endpoint = rx.recv_timeout(Duration::from_secs(30)).expect("the browser announces its debugging port");
    Browser { child, endpoint }
}

fn command(url: &str, submit: bool) -> FillCommand {
    command_for(url, url, submit)
}

/// A login for `site`, to be filled on the page at `url`.
fn command_for(url: &str, site: &str, submit: bool) -> FillCommand {
    FillCommand {
        id: "f-1".into(),
        url: url.to_string(),
        rules: fill_rules(&[site.to_string()]),
        username: "octo".into(),
        password: "hunter2".into(),
        code: String::new(),
        submit,
    }
}

#[tokio::test]
#[ignore = "needs a Chromium (CHROME=/path/to/chromium)"]
async fn fills_the_sign_in_page_through_the_debugging_port() {
    let (port, posts) = serve_page();
    let url = format!("http://127.0.0.1:{port}/login");
    let browser = start_browser(&url);
    assert_eq!(cdp::browser(&browser.endpoint).await.unwrap(), "chrome");

    // The page takes a moment to appear in the tab list.
    let deadline = Instant::now() + Duration::from_secs(20);
    let filled = loop {
        match cdp::fill(&browser.endpoint, &command(&url, false)).await {
            Ok(done) if done.outcome == FillOutcome::Filled => break done,
            Ok(_) | Err(CdpError::NoTab(_)) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(500)).await
            }
            other => panic!("{other:?}"),
        }
    };
    assert!(!filled.submitted);
    assert_eq!(filled.browser, "chrome");

    // Another website is not filled, whatever tab is open.
    let other = command_for(&url, "https://github.com", false);
    assert!(matches!(cdp::fill(&browser.endpoint, &other).await, Err(CdpError::NoTab(_))));

    // Submitting posts the login back to the page's server.
    let done = cdp::fill(&browser.endpoint, &command(&url, true)).await.unwrap();
    assert_eq!((done.outcome, done.submitted), (FillOutcome::Filled, true));
    let deadline = Instant::now() + Duration::from_secs(10);
    while posts.lock().unwrap().is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let posted = posts.lock().unwrap().clone();
    assert_eq!(posted, ["user=octo&pw=hunter2"]);
}
