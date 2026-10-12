// Opens 2Secret in a small window when a page asks for a passkey. The origin
// comes from the browser (the sender of the message), never from the page.
// The 2Secret window answers the tab itself; closing it cancels the request.
const api = globalThis.browser ?? globalThis.chrome;
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
