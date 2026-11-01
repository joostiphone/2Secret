//! Filling a login through the Chrome DevTools Protocol: the browser on the
//! agent's computer is started with `--remote-debugging-port`, and this
//! module finds the tab whose address the item's fill rules allow, opens
//! the page's debugging socket and runs the extension's own `twosecretFill`
//! (`extension/fill.js`) in an isolated world of every frame. Each frame
//! checks its own address, as in the extension, so credentials never reach
//! a frame of another site. The model only hears the outcome.
//!
//! Chromium based browsers only (Chrome, Edge, Brave, Chromium); frames in
//! other processes (cross-site iframes) are not reached.

use std::fmt;

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message;
use twosecret_core::agent::{FillCommand, FillOutcome};
use twosecret_core::util::{fill_allowed, url_host};
use zeroize::Zeroizing;

/// The extension's filling code; `twosecretFill` is self-contained.
const FILL_JS: &str = include_str!("../../../extension/fill.js");

/// How long one browser call may take.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

#[derive(Debug)]
pub enum CdpError {
    /// No browser answers at the debugging port.
    Unreachable(String),
    /// No open tab for the item's website.
    NoTab(String),
    Protocol(String),
}

impl fmt::Display for CdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CdpError::Unreachable(e) => write!(
                f,
                "no browser answers at the debugging port ({e}): start the browser with --remote-debugging-port and \
                 pass the same port to 2secret mcp --remote --cdp"
            ),
            CdpError::NoTab(host) => {
                write!(f, "no open tab for {host} in the browser: open the sign-in page there first")
            }
            CdpError::Protocol(e) => write!(f, "the browser's debugging protocol failed: {e}"),
        }
    }
}

impl std::error::Error for CdpError {}

/// How a fill went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CdpFill {
    pub outcome: FillOutcome,
    pub submitted: bool,
    /// `chrome`, `edge`, `brave`, ... as the browser names itself.
    pub browser: String,
}

/// `9222`, `127.0.0.1:9222`, `http://127.0.0.1:9222` → the HTTP address of
/// the debugging port.
pub fn endpoint_url(endpoint: &str) -> String {
    let e = endpoint.trim().trim_end_matches('/');
    if e.starts_with("http://") || e.starts_with("https://") {
        e.to_string()
    } else if e.chars().all(|c| c.is_ascii_digit()) {
        format!("http://127.0.0.1:{e}")
    } else {
        format!("http://{e}")
    }
}

#[derive(Deserialize)]
struct Target {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    url: String,
    #[serde(rename = "webSocketDebuggerUrl")]
    socket: Option<String>,
}

#[derive(Deserialize)]
struct Version {
    #[serde(rename = "Browser", default)]
    browser: String,
}

fn http() -> reqwest::Client {
    reqwest::Client::builder().timeout(TIMEOUT).build().unwrap_or_default()
}

/// `Chrome/130.0.6723.58` → `chrome`; `HeadlessChrome/…` → `chrome`;
/// `Edg/…` → `edge`.
fn browser_name(version: &str) -> String {
    let product = version.split('/').next().unwrap_or(version).trim().to_lowercase();
    match product.as_str() {
        "chrome" | "headlesschrome" | "chromium" => "chrome".to_string(),
        "edg" | "edge" => "edge".to_string(),
        "" => "browser".to_string(),
        other => other.to_string(),
    }
}

/// The browser behind the debugging port, as `browser_name` names it.
pub async fn browser(endpoint: &str) -> Result<String, CdpError> {
    let base = endpoint_url(endpoint);
    let version: Version = http()
        .get(format!("{base}/json/version"))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| CdpError::Unreachable(e.to_string()))?
        .json()
        .await
        .map_err(|e| CdpError::Protocol(e.to_string()))?;
    Ok(browser_name(&version.browser))
}

/// Fill `command` into the first open tab its rules allow.
pub async fn fill(endpoint: &str, command: &FillCommand) -> Result<CdpFill, CdpError> {
    let base = endpoint_url(endpoint);
    let browser = browser(endpoint).await?;
    let targets: Vec<Target> = http()
        .get(format!("{base}/json/list"))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| CdpError::Unreachable(e.to_string()))?
        .json()
        .await
        .map_err(|e| CdpError::Protocol(e.to_string()))?;
    let host = url_host(&command.url).unwrap_or_else(|| command.url.clone());
    let pages: Vec<&Target> = targets
        .iter()
        .filter(|t| t.kind == "page" && t.socket.is_some() && fill_allowed(&t.url, &command.rules))
        .collect();
    // The page the agent named first, then any the rules allow.
    let target = pages
        .iter()
        .find(|t| t.url == command.url)
        .or_else(|| pages.first())
        .copied()
        .ok_or_else(|| CdpError::NoTab(host.clone()))?;
    let socket = target.socket.clone().expect("filtered");
    let mut session = Session::connect(&socket).await?;
    let tree = session.call("Page.getFrameTree", json!({})).await?;
    let mut frames = Vec::new();
    collect_frames(&tree["frameTree"], &mut frames);
    if frames.is_empty() {
        return Err(CdpError::Protocol("the page has no frames".into()));
    }
    let expression = Zeroizing::new(format!(
        "(() => {{ {FILL_JS}\nreturn globalThis.twosecretFill({}, {}, {}, {}, {}); }})()",
        json_literal(&command.username),
        json_literal(&command.password),
        json_literal(&command.code),
        serde_json::to_string(&command.rules).unwrap_or_else(|_| "[]".into()),
        command.submit
    ));
    let mut nothing = false;
    for frame in frames {
        let world = session
            .call(
                "Page.createIsolatedWorld",
                json!({ "frameId": frame, "worldName": "2secret-fill", "grantUniveralAccess": false }),
            )
            .await;
        let Ok(world) = world else { continue };
        let Some(context) = world["executionContextId"].as_i64() else { continue };
        let result = session
            .call(
                "Runtime.evaluate",
                json!({ "expression": &*expression, "contextId": context, "returnByValue": true }),
            )
            .await;
        let Ok(result) = result else { continue };
        if result.get("exceptionDetails").is_some() {
            continue;
        }
        let value = &result["result"]["value"];
        match value["outcome"].as_str() {
            Some("filled") => {
                let submitted = value["submitted"].as_bool().unwrap_or(false);
                return Ok(CdpFill { outcome: FillOutcome::Filled, submitted, browser });
            }
            Some("nothing") => nothing = true,
            _ => {}
        }
    }
    Ok(CdpFill { outcome: if nothing { FillOutcome::Nothing } else { FillOutcome::NoTab }, submitted: false, browser })
}

/// A string as a JavaScript literal (JSON is one).
fn json_literal(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

fn collect_frames(node: &Value, out: &mut Vec<String>) {
    if let Some(id) = node["frame"]["id"].as_str() {
        out.push(id.to_string());
    }
    if let Some(children) = node["childFrames"].as_array() {
        for child in children {
            collect_frames(child, out);
        }
    }
}

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// One page's debugging socket.
struct Session {
    socket: Socket,
    next_id: u64,
}

impl Session {
    async fn connect(url: &str) -> Result<Self, CdpError> {
        let connect = tokio_tungstenite::connect_async(url);
        let (socket, _) = tokio::time::timeout(TIMEOUT, connect)
            .await
            .map_err(|_| CdpError::Unreachable("timeout".into()))?
            .map_err(|e| CdpError::Unreachable(e.to_string()))?;
        Ok(Self { socket, next_id: 1 })
    }

    /// One command; events in between are skipped.
    async fn call(&mut self, method: &str, params: Value) -> Result<Value, CdpError> {
        let id = self.next_id;
        self.next_id += 1;
        let text = json!({ "id": id, "method": method, "params": params }).to_string();
        self.socket.send(Message::Text(text.into())).await.map_err(|e| CdpError::Protocol(e.to_string()))?;
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            let next = tokio::time::timeout_at(deadline, self.socket.next())
                .await
                .map_err(|_| CdpError::Protocol(format!("{method}: no answer")))?;
            let message = match next {
                Some(Ok(Message::Text(t))) => t,
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(CdpError::Protocol(e.to_string())),
                None => return Err(CdpError::Protocol("the browser closed the connection".into())),
            };
            let value: Value = serde_json::from_str(&message).map_err(|e| CdpError::Protocol(e.to_string()))?;
            if value["id"].as_u64() != Some(id) {
                continue;
            }
            if let Some(error) = value.get("error") {
                let text = error["message"].as_str().unwrap_or("error").to_string();
                return Err(CdpError::Protocol(format!("{method}: {text}")));
            }
            return Ok(value["result"].clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_and_names() {
        assert_eq!(endpoint_url("9222"), "http://127.0.0.1:9222");
        assert_eq!(endpoint_url("localhost:9222/"), "http://localhost:9222");
        assert_eq!(endpoint_url("http://127.0.0.1:9333"), "http://127.0.0.1:9333");
        assert_eq!(browser_name("Chrome/130.0.6723.58"), "chrome");
        assert_eq!(browser_name("HeadlessChrome/130.0.6723.58"), "chrome");
        assert_eq!(browser_name("Edg/130.0"), "edge");
        assert_eq!(browser_name(""), "browser");
        assert_eq!(json_literal("it's \"x\"\u{2028}"), "\"it's \\\"x\\\"\u{2028}\"");
    }

    #[test]
    fn frames_are_collected_depth_first() {
        let tree = json!({ "frame": { "id": "a" }, "childFrames": [
            { "frame": { "id": "b" }, "childFrames": [{ "frame": { "id": "c" } }] },
            { "frame": { "id": "d" } }
        ] });
        let mut out = Vec::new();
        collect_frames(&tree, &mut out);
        assert_eq!(out, ["a", "b", "c", "d"]);
    }

    #[test]
    fn fill_script_is_self_contained() {
        assert!(FILL_JS.contains("function twosecretFill("));
        assert!(FILL_JS.contains("globalThis.twosecretFill = twosecretFill"));
    }
}
