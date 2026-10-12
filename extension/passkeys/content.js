// Relays passkey requests between the page script (page.js) and 2Secret.
// Only requests this page made get an answer, and only on this page.
(() => {
  "use strict";
  const api = globalThis.browser ?? globalThis.chrome;
  const CHANNEL = "2secret-passkey";
  const pending = new Set();

  const reply = (id, payload) => {
    if (!pending.delete(id)) return;
    window.postMessage({ ...payload, channel: CHANNEL, direction: "to-page", id }, window.location.origin);
  };

  window.addEventListener("message", async (e) => {
    const d = e.data;
    if (e.source !== window || !d || d.channel !== CHANNEL || d.direction !== "to-extension") return;
    if (typeof d.id !== "string" || pending.has(d.id) || pending.size >= 4) return;
    pending.add(d.id);
    try {
      const settings = await api.storage.local.get("2s-passkeys");
      if (settings["2s-passkeys"] === "off") return reply(d.id, { fallback: true });
      const r = await api.runtime.sendMessage({ type: "2s-passkey-request", id: d.id, kind: d.kind, options: d.options });
      if (!r || !r.opened) reply(d.id, r && r.error ? { error: r.error } : { fallback: true });
    } catch (err) {
      reply(d.id, { fallback: true });
    }
  });

  api.runtime.onMessage.addListener((msg) => {
    if (!msg || msg.type !== "2s-passkey-result" || typeof msg.id !== "string") return;
    const { result, fallback, error } = msg;
    reply(msg.id, { result, fallback, error });
  });
})();
