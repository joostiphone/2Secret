//! Browser extension integration: current tab, autofill and keeping the
//! vault unlocked between popup openings (in `chrome.storage.session`, which
//! lives in browser memory only and is cleared when the browser closes).
//!
//! All functions are no-ops outside the extension build.

/// Outcome of filling the active tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(all(feature = "extension", target_arch = "wasm32")), allow(dead_code))]
pub enum FillResult {
    Filled,
    NothingToFill,
    /// The page (or the frame with the form) is not one of the item's websites.
    WrongSite,
}

#[cfg(all(feature = "extension", target_arch = "wasm32"))]
mod imp {
    use super::FillResult;
    use twosecret_core::util::FillRule;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen(inline_js = r#"
const api = globalThis.browser ?? globalThis.chrome;

export async function activeTabUrl() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  return tab && tab.url ? tab.url : "";
}

// Is a page location allowed to receive an item's credentials? `rules` are
// the item's registrable domains, with the https and port requirements.
function twosecretAllowed(loc, rules) {
  const host = (loc.hostname || "").toLowerCase().replace(/\.$/, "");
  if (!host || !/^https?:$/.test(loc.protocol)) return false;
  return rules.some((r) =>
    (host === r.domain || host.endsWith("." + r.domain))
    && (!r.https || loc.protocol === "https:")
    && (r.port === null || (loc.port || (loc.protocol === "https:" ? "443" : "80")) === String(r.port)));
}

// Runs inside every frame of the page (serialised by the browser, not eval'd
// here, so it has to be self-contained and repeats the check above). Each
// frame checks its own address, so credentials never reach a frame from
// another site or a page the tab navigated to in the meantime.
function twosecretFill(username, password, code, rules) {
  const allowed = (loc) => {
    const host = (loc.hostname || "").toLowerCase().replace(/\.$/, "");
    if (!host || !/^https?:$/.test(loc.protocol)) return false;
    return rules.some((r) =>
      (host === r.domain || host.endsWith("." + r.domain))
      && (!r.https || loc.protocol === "https:")
      && (r.port === null || (loc.port || (loc.protocol === "https:" ? "443" : "80")) === String(r.port)));
  };
  if (!allowed(window.location)) return "mismatch";
  const visible = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length)
    && getComputedStyle(el).visibility !== "hidden" && !el.disabled && !el.readOnly;
  const setValue = (el, value) => {
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const hint = (el) => `${el.name} ${el.id} ${el.placeholder || ""} ${el.getAttribute("aria-label") || ""}`.toLowerCase();
  const inputs = Array.from(document.querySelectorAll("input")).filter(visible);
  const passwords = inputs.filter((i) => i.type === "password");
  const texty = (i) => ["text", "email", "tel", ""].includes(i.type);
  let filled = false;
  if (password && passwords.length) {
    setValue(passwords[0], password);
    filled = true;
  }
  if (username) {
    let user = inputs.find((i) => texty(i) && (i.autocomplete || "").includes("username"))
      || inputs.find((i) => texty(i) && /user|e-?mail|login|account|identifier/.test(hint(i)));
    if (!user && passwords.length) {
      const idx = inputs.indexOf(passwords[0]);
      user = inputs.slice(0, idx).reverse().find(texty);
    }
    if (!user && !passwords.length) {
      user = inputs.find(texty);
    }
    if (user) {
      setValue(user, username);
      filled = true;
    }
  }
  if (code && !passwords.length) {
    const otp = inputs.find((i) => (i.autocomplete || "") === "one-time-code")
      || inputs.find((i) => texty(i) && /otp|totp|2fa|mfa|code|token|verification/.test(hint(i)));
    if (otp) {
      setValue(otp, code);
      filled = true;
    }
  }
  return filled ? "filled" : "nothing";
}

export async function fillActiveTab(username, password, code, rulesJson) {
  const rules = JSON.parse(rulesJson);
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  if (!tab || tab.id === undefined || !tab.url) return "nothing";
  // The tab may have navigated since the popup opened: check it again now.
  if (!twosecretAllowed(new URL(tab.url), rules)) return "mismatch";
  const results = await api.scripting.executeScript({
    target: { tabId: tab.id, allFrames: true },
    func: twosecretFill,
    args: [username, password, code, rules],
  });
  const outcomes = results.map((r) => r && r.result);
  if (outcomes.includes("filled")) return "filled";
  return outcomes.includes("nothing") ? "nothing" : "mismatch";
}

export async function sessionGet(key) {
  const r = await api.storage.session.get(key);
  return r[key] ?? null;
}
export async function sessionSet(key, value) {
  await api.storage.session.set({ [key]: value });
}
export async function sessionRemove(key) {
  await api.storage.session.remove(key);
}
export function closePopup() {
  window.close();
}

// Passkey requests: background.js stores them and opens this page with
// #passkey=<id>.
export async function passkeyRequest() {
  const m = /^#passkey=([0-9a-f-]{36})$/.exec(window.location.hash);
  if (!m) return null;
  const key = "2s-passkey:" + m[1];
  return (await api.storage.session.get(key))[key] ?? null;
}
export async function answerPasskey(rid, payloadJson) {
  const key = "2s-passkey:" + rid;
  const stored = (await api.storage.session.get(key))[key];
  if (stored) {
    const request = JSON.parse(stored);
    await api.storage.session.remove(key);
    const message = { ...JSON.parse(payloadJson), type: "2s-passkey-result", id: request.page_id };
    try {
      await api.tabs.sendMessage(request.tab_id, message, { frameId: 0 });
    } catch (e) {
      // The tab was closed meanwhile.
    }
  }
  window.close();
}
export async function passkeysEnabled() {
  return (await api.storage.local.get("2s-passkeys"))["2s-passkeys"] !== "off";
}
export async function setPasskeysEnabled(on) {
  await api.storage.local.set({ "2s-passkeys": on ? "on" : "off" });
}
"#)]
    extern "C" {
        #[wasm_bindgen(catch, js_name = activeTabUrl)]
        async fn active_tab_url() -> Result<JsValue, JsValue>;
        #[wasm_bindgen(catch, js_name = fillActiveTab)]
        async fn fill_active_tab(
            username: String,
            password: String,
            code: String,
            rules: String,
        ) -> Result<JsValue, JsValue>;
        #[wasm_bindgen(catch, js_name = sessionGet)]
        async fn session_get(key: &str) -> Result<JsValue, JsValue>;
        #[wasm_bindgen(catch, js_name = sessionSet)]
        async fn session_set(key: &str, value: String) -> Result<JsValue, JsValue>;
        #[wasm_bindgen(catch, js_name = sessionRemove)]
        async fn session_remove(key: &str) -> Result<JsValue, JsValue>;
        #[wasm_bindgen(js_name = closePopup)]
        fn close_popup();
        #[wasm_bindgen(catch, js_name = passkeyRequest)]
        async fn passkey_request() -> Result<JsValue, JsValue>;
        #[wasm_bindgen(catch, js_name = answerPasskey)]
        async fn answer_passkey(rid: &str, payload: String) -> Result<JsValue, JsValue>;
        #[wasm_bindgen(catch, js_name = passkeysEnabled)]
        async fn passkeys_enabled_js() -> Result<JsValue, JsValue>;
        #[wasm_bindgen(catch, js_name = setPasskeysEnabled)]
        async fn set_passkeys_enabled_js(on: bool) -> Result<JsValue, JsValue>;
    }

    pub async fn pending_passkey() -> Option<String> {
        passkey_request().await.ok().and_then(|v| v.as_string())
    }

    pub async fn answer(rid: &str, payload: String) {
        let _ = answer_passkey(rid, payload).await;
    }

    pub async fn passkeys_enabled() -> bool {
        passkeys_enabled_js().await.ok().and_then(|v| v.as_bool()).unwrap_or(true)
    }

    pub async fn set_passkeys_enabled(on: bool) {
        let _ = set_passkeys_enabled_js(on).await;
    }

    pub async fn tab_url() -> Option<String> {
        active_tab_url().await.ok().and_then(|v| v.as_string()).filter(|s| s.starts_with("http"))
    }

    pub async fn fill(username: &str, password: &str, code: &str, rules: &[FillRule]) -> FillResult {
        let rules = serde_json::to_string(rules).unwrap_or_else(|_| "[]".into());
        match fill_active_tab(username.into(), password.into(), code.into(), rules)
            .await
            .ok()
            .and_then(|v| v.as_string())
        {
            Some(r) if r == "filled" => FillResult::Filled,
            Some(r) if r == "mismatch" => FillResult::WrongSite,
            _ => FillResult::NothingToFill,
        }
    }

    pub async fn store(key: &str, value: String) {
        let _ = session_set(key, value).await;
    }

    pub async fn load(key: &str) -> Option<String> {
        session_get(key).await.ok().and_then(|v| v.as_string())
    }

    pub async fn remove(key: &str) {
        let _ = session_remove(key).await;
    }

    pub fn close() {
        close_popup();
    }
}

#[cfg(not(all(feature = "extension", target_arch = "wasm32")))]
mod imp {
    pub async fn tab_url() -> Option<String> {
        None
    }
    pub async fn fill(
        _username: &str,
        _password: &str,
        _code: &str,
        _rules: &[twosecret_core::util::FillRule],
    ) -> super::FillResult {
        super::FillResult::NothingToFill
    }
    pub async fn store(_key: &str, _value: String) {}
    pub async fn load(_key: &str) -> Option<String> {
        None
    }
    pub async fn remove(_key: &str) {}
    pub fn close() {}
    pub async fn pending_passkey() -> Option<String> {
        None
    }
    pub async fn answer(_rid: &str, _payload: String) {}
    pub async fn passkeys_enabled() -> bool {
        false
    }
    pub async fn set_passkeys_enabled(_on: bool) {}
}

use serde::{Deserialize, Serialize};
use twosecret_core::crypto::SymmetricKey;
use twosecret_core::util::now;

pub use imp::{close, fill, passkeys_enabled, set_passkeys_enabled, tab_url};

/// A website's passkey request, waiting for the user in this window.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct PasskeyRequest {
    pub rid: String,
    /// "create" or "get".
    pub kind: String,
    /// The page's origin, as reported by the browser.
    pub origin: String,
    pub options: serde_json::Value,
}

/// How the window answers the page.
#[cfg_attr(not(all(feature = "extension", target_arch = "wasm32")), allow(dead_code))]
pub enum PasskeyAnswer {
    /// A new passkey (`Registration`) or a sign-in (`Assertion`).
    Result(serde_json::Value),
    /// Let the browser handle it (security key, phone, ...).
    Fallback,
    /// A DOMException name, e.g. "NotAllowedError".
    Error(&'static str),
}

/// The passkey request this window was opened for, if any.
pub async fn pending_passkey() -> Option<PasskeyRequest> {
    serde_json::from_str(&imp::pending_passkey().await?).ok()
}

/// Answer the page and close this window.
pub async fn answer_passkey(rid: &str, answer: PasskeyAnswer) {
    let payload = match answer {
        PasskeyAnswer::Result(r) => serde_json::json!({ "result": r }),
        PasskeyAnswer::Fallback => serde_json::json!({ "fallback": true }),
        PasskeyAnswer::Error(name) => serde_json::json!({ "error": name }),
    };
    // A new passkey must be stored before the window closes: the website
    // keeps the public key either way.
    crate::platform::flush().await;
    imp::answer(rid, payload.to_string()).await;
}

/// Is this the browser extension build?
pub const ENABLED: bool = cfg!(feature = "extension");

const UNLOCK_KEY: &str = "2secret-unlock";

#[derive(Serialize, Deserialize)]
struct Cached {
    account_id: String,
    key: String,
    expires_at: i64,
}

/// Keep the vault unlocked for `ttl_secs` (extension only).
pub async fn remember_unlock(account_id: &str, key: &SymmetricKey, ttl_secs: i64) {
    if !ENABLED {
        return;
    }
    let cached = Cached { account_id: account_id.to_string(), key: key.to_b64(), expires_at: now() + ttl_secs };
    if let Ok(json) = serde_json::to_string(&cached) {
        imp::store(UNLOCK_KEY, json).await;
    }
}

/// The cached account key, if still valid.
pub async fn cached_unlock(account_id: &str) -> Option<SymmetricKey> {
    if !ENABLED {
        return None;
    }
    let json = imp::load(UNLOCK_KEY).await?;
    let cached: Cached = serde_json::from_str(&json).ok()?;
    if cached.account_id != account_id || cached.expires_at < now() {
        imp::remove(UNLOCK_KEY).await;
        return None;
    }
    SymmetricKey::from_b64(&cached.key).ok()
}

pub async fn forget_unlock() {
    if ENABLED {
        imp::remove(UNLOCK_KEY).await;
    }
}
