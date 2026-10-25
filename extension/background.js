// The extension's background: the connection to the 2Secret app (logins the
// user allows an AI agent to use are filled here) and passkey requests.
const api = globalThis.browser ?? globalThis.chrome;

// --- The browser connection ---------------------------------------------
//
// The 2Secret app registers itself as this extension's native messaging
// host (Settings → Desktop app → Browser connection). The host connects to
// the app and hands us the logins the user allowed; fill.js puts them in the
// matching active tab. The host pings every 20 s, which keeps this worker
// alive; when the port drops (the app or the host is gone) we try again with
// a growing pause, and a watchdog alarm reconnects after the browser or the
// worker restarted.

if (typeof importScripts === "function") importScripts("fill.js");

const HOST_NAME = "io.github.joostiphone.twosecret";
const RECONNECT = "2s-native-reconnect";
const WATCH = "2s-native-watch";
let port = null;
let pauseMinutes = 0.5;

async function browserName() {
  try {
    if (api.runtime.getBrowserInfo) return (await api.runtime.getBrowserInfo()).name.toLowerCase();
  } catch (e) {
    // Not Firefox.
  }
  const brands = ((navigator.userAgentData && navigator.userAgentData.brands) || []).map((b) => b.brand.toLowerCase());
  const known = [["edge", "edge"], ["brave", "brave"], ["vivaldi", "vivaldi"], ["opera", "opera"], ["arc", "arc"],
    ["google chrome", "chrome"], ["chromium", "chromium"]];
  for (const [needle, name] of known) {
    if (brands.some((b) => b.includes(needle))) return name;
  }
  return "chrome";
}

function scheduleReconnect() {
  api.alarms.create(RECONNECT, { delayInMinutes: pauseMinutes });
  pauseMinutes = Math.min(pauseMinutes * 2, 5);
}

async function onHostMessage(p, msg) {
  if (!msg || typeof msg !== "object") return;
  if (msg.type === "status") {
    if (msg.app) pauseMinutes = 0.5;
    await api.storage.session.set({ "2s-app": JSON.stringify(msg) });
  } else if (msg.type === "fill") {
    const result = await globalThis.twosecretHandleFill(msg);
    try {
      p.postMessage({ type: "fill_result", ...result });
    } catch (e) {
      // The host is gone; the app lets the login expire.
    }
  }
}

function connect() {
  if (port) return;
  let p;
  try {
    p = api.runtime.connectNative(HOST_NAME);
  } catch (e) {
    scheduleReconnect();
    return;
  }
  port = p;
  p.onMessage.addListener((msg) => {
    onHostMessage(p, msg).catch(() => {});
  });
  p.onDisconnect.addListener(() => {
    if (port === p) port = null;
    scheduleReconnect();
  });
  browserName().then((name) => {
    try {
      p.postMessage({ type: "hello", extension: api.runtime.getManifest().version, browser: name });
    } catch (e) {
      // Disconnected already.
    }
  });
}

api.alarms.create(WATCH, { periodInMinutes: 1 });
api.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === RECONNECT) connect();
  // The watchdog leaves a scheduled retry alone (the app may be off).
  if (alarm.name === WATCH && !port && !(await api.alarms.get(RECONNECT))) connect();
});
api.runtime.onStartup.addListener(connect);
api.runtime.onInstalled.addListener(connect);
connect();
globalThis.twosecretConnect = connect;

// --- Passkeys -------------------------------------------------------------
//
// Opens 2Secret in a small window when a page asks for a passkey. The origin
// comes from the browser (the sender of the message), never from the page.
// The 2Secret window answers the tab itself; closing it cancels the request.
const PREFIX = "2s-passkey:";

async function cancel(rid, payload) {
  const key = PREFIX + rid;
  const stored = (await api.storage.session.get(key))[key];
  if (!stored) return;
  await api.storage.session.remove(key);
  const request = JSON.parse(stored);
  try {
    await api.tabs.sendMessage(request.tab_id, { type: "2s-passkey-result", id: request.page_id, ...payload }, { frameId: 0 });
  } catch (e) {
    // The tab is gone.
  }
}

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.type !== "2s-passkey-request") return false;
  if (!sender.tab || sender.tab.id === undefined || sender.frameId !== 0 || !sender.url) {
    sendResponse({ opened: false });
    return false;
  }
  (async () => {
    const origin = sender.origin && sender.origin !== "null" ? sender.origin : new URL(sender.url).origin;
    const rid = crypto.randomUUID();
    const request = {
      rid,
      page_id: String(msg.id),
      kind: msg.kind === "create" ? "create" : "get",
      origin,
      tab_id: sender.tab.id,
      options: msg.options ?? {},
    };
    // One request per tab at a time.
    const all = await api.storage.session.get(null);
    for (const [key, value] of Object.entries(all)) {
      if (key.startsWith(PREFIX) && JSON.parse(value).tab_id === sender.tab.id) await cancel(key.slice(PREFIX.length), { error: "NotAllowedError" });
    }
    await api.storage.session.set({ [PREFIX + rid]: JSON.stringify(request) });
    const win = await api.windows.create({
      url: api.runtime.getURL(`index.html#passkey=${rid}`),
      type: "popup",
      width: 420,
      height: 640,
      focused: true,
    });
    await api.storage.session.set({ [`2s-passkey-window:${win.id}`]: rid });
    sendResponse({ opened: true });
  })().catch(() => sendResponse({ opened: false }));
  return true;
});

api.windows.onRemoved.addListener(async (windowId) => {
  const key = `2s-passkey-window:${windowId}`;
  const rid = (await api.storage.session.get(key))[key];
  if (!rid) return;
  await api.storage.session.remove(key);
  await cancel(rid, { error: "NotAllowedError" });
});
