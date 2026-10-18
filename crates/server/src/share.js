// Opens a 2Secret share link: /s/<id>#<key>. The key in the fragment never
// reaches the server; the content is decrypted here with WebCrypto, exactly as
// twosecret_core::share encrypted it (AES-256-GCM, SHA-256, PBKDF2-SHA256).
"use strict";

(function () {
  const dutch = (navigator.language || "").toLowerCase().startsWith("nl");
  const T = dutch
    ? {
        loading: "Bezig…",
        askTitle: "Er is iets met je gedeeld",
        askInfo: "Iemand deelt dit met je via 2Secret. Het is versleuteld; alleen deze link kan het openen.",
        expires: "Verloopt op {date}.",
        viewsLeft: "Kan nog {n} keer worden geopend.",
        lastView: "Kan nog één keer worden geopend: daarna is het weg.",
        password: "Wachtwoord van de link",
        show: "Tonen",
        wrongPassword: "Dat wachtwoord klopt niet.",
        wrongKey: "Deze link is niet compleet of klopt niet.",
        goneTitle: "Deze link werkt niet meer",
        goneText: "Hij is verlopen, ingetrokken of te vaak geopend. Vraag de afzender om een nieuwe link.",
        incompleteTitle: "Deze link is niet compleet",
        incompleteText: "Het deel na # ontbreekt; zonder dat deel kan niemand de inhoud openen. Kopieer de hele link.",
        tooMany: "Te veel pogingen. Probeer het over een paar minuten opnieuw.",
        failed: "Er ging iets mis. Probeer het opnieuw.",
        noCrypto: "Deze browser kan de inhoud niet ontsleutelen. Open de link in een recente browser.",
        reveal: "Tonen",
        hide: "Verbergen",
        copy: "Kopiëren",
        copied: "Gekopieerd",
        notes: "Notities",
        websites: "Websites",
        nowGone: "Deze link is nu opgebruikt. Bewaar wat je nodig hebt.",
        footer: "End-to-end versleuteld met 2Secret. De server heeft deze inhoud nooit kunnen lezen.",
      }
    : {
        loading: "Loading…",
        askTitle: "Something was shared with you",
        askInfo: "Someone shares this with you through 2Secret. It is encrypted; only this link can open it.",
        expires: "Expires on {date}.",
        viewsLeft: "Can be opened {n} more times.",
        lastView: "Can be opened once more: then it is gone.",
        password: "Password of the link",
        show: "Show",
        wrongPassword: "That password is not right.",
        wrongKey: "This link is incomplete or wrong.",
        goneTitle: "This link no longer works",
        goneText: "It expired, was revoked or was opened too often. Ask the sender for a new link.",
        incompleteTitle: "This link is incomplete",
        incompleteText: "The part after # is missing; nobody can open the content without it. Copy the whole link.",
        tooMany: "Too many attempts. Try again in a few minutes.",
        failed: "Something went wrong. Please try again.",
        noCrypto: "This browser cannot decrypt the content. Open the link in a recent browser.",
        reveal: "Show",
        hide: "Hide",
        copy: "Copy",
        copied: "Copied",
        notes: "Notes",
        websites: "Websites",
        nowGone: "This link is used up now. Keep what you need.",
        footer: "End-to-end encrypted with 2Secret. The server could never read this content.",
      };
  if (dutch) document.documentElement.lang = "nl";

  const $ = (id) => document.getElementById(id);
  const text = (el, value) => {
    el.textContent = value;
    return el;
  };
  const show = (section) => {
    for (const s of ["loading", "ask", "content", "gone"]) $(s).classList.toggle("hidden", s !== section);
  };
  const enc = new TextEncoder();

  const id = location.pathname.split("/").pop() || "";
  const linkKey = location.hash.slice(1);
  text($("loading-text"), T.loading);
  text($("footer"), T.footer);

  function fromB64url(s) {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  }
  function toB64url(bytes) {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function concat(parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) {
      out.set(p, at);
      at += p.length;
    }
    return out;
  }
  const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

  async function contentKey(password) {
    const parts = [enc.encode("2secret/share/v1/key"), fromB64url(linkKey)];
    if (password) {
      const base = await crypto.subtle.importKey("raw", enc.encode(password.normalize("NFKD")), "PBKDF2", false, ["deriveBits"]);
      const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt: enc.encode("2secret share " + id), iterations: 600000 },
        base,
        256,
      );
      parts.push(new Uint8Array(bits));
    }
    return sha256(concat(parts));
  }

  function gone(title, body) {
    text($("gone-title"), title);
    text($("gone-text"), body);
    show("gone");
  }

  function availability(info) {
    const lines = [T.expires.replace("{date}", new Date(info.expires_at * 1000).toLocaleString())];
    if (info.views_left === 1) lines.push(T.lastView);
    else if (info.views_left !== null && info.views_left !== undefined) lines.push(T.viewsLeft.replace("{n}", info.views_left));
    return lines.join(" ");
  }

  function field(label, value, concealed) {
    const box = document.createElement("div");
    box.className = "field";
    box.appendChild(text(document.createElement("label"), label));
    const row = document.createElement("div");
    row.className = "row";
    const shown = text(document.createElement("div"), concealed ? "••••••••••" : value);
    shown.className = "value";
    row.appendChild(shown);
    if (concealed) {
      const reveal = text(document.createElement("button"), T.reveal);
      let visible = false;
      reveal.addEventListener("click", () => {
        visible = !visible;
        text(shown, visible ? value : "••••••••••");
        text(reveal, visible ? T.hide : T.reveal);
      });
      row.appendChild(reveal);
    }
    const copy = text(document.createElement("button"), T.copy);
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(value);
        text(copy, T.copied);
        setTimeout(() => text(copy, T.copy), 1500);
      } catch (_) {
        /* The browser refused; the value can still be selected. */
      }
    });
    row.appendChild(copy);
    box.appendChild(row);
    return box;
  }

  function render(item, viewsLeft) {
    text($("title"), item.title || "2Secret");
    text($("content-info"), viewsLeft === 0 ? T.nowGone : "");
    const fields = $("fields");
    for (const f of item.fields || []) fields.appendChild(field(f.label, f.value, !!f.concealed));
    const urls = item.urls || [];
    if (urls.length) {
      const box = document.createElement("div");
      box.className = "field";
      box.appendChild(text(document.createElement("label"), T.websites));
      for (const u of urls) {
        // Only web addresses become links (never javascript: and the like).
        const web = /^https?:\/\//i.test(u);
        const el = text(document.createElement(web ? "a" : "span"), u);
        if (web) {
          el.href = u;
          el.rel = "noopener noreferrer";
          el.target = "_blank";
        }
        box.appendChild(el);
        box.appendChild(document.createElement("br"));
      }
      fields.appendChild(box);
    }
    if (item.notes) {
      const box = document.createElement("div");
      box.className = "field";
      box.appendChild(text(document.createElement("label"), T.notes));
      const notes = text(document.createElement("div"), item.notes);
      notes.className = "notes";
      box.appendChild(notes);
      fields.appendChild(box);
    }
    show("content");
  }

  async function openShare(info) {
    const button = $("show");
    const error = $("ask-error");
    button.disabled = true;
    error.classList.add("hidden");
    try {
      const password = info.password ? $("password").value : "";
      const key = await contentKey(password);
      const proof = toB64url(await sha256(concat([enc.encode("2secret/share/v1/proof"), key])));
      const response = await fetch("/api/v1/shares/" + id + "/open", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ proof }),
      });
      if (response.status === 404) return gone(T.goneTitle, T.goneText);
      if (response.status === 403) {
        text(error, info.password ? T.wrongPassword : T.wrongKey).classList.remove("hidden");
        return;
      }
      if (response.status === 429) {
        text(error, T.tooMany).classList.remove("hidden");
        return;
      }
      if (!response.ok) throw new Error("HTTP " + response.status);
      const answer = await response.json();
      const data = fromB64url(answer.data);
      const aesKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: data.slice(0, 12), additionalData: enc.encode("2secret/share/v1:" + id) },
        aesKey,
        data.slice(12),
      );
      render(JSON.parse(new TextDecoder().decode(plain)), answer.views_left);
    } catch (_) {
      text(error, T.failed).classList.remove("hidden");
    } finally {
      button.disabled = false;
    }
  }

  async function start() {
    if (!linkKey || !/^[A-Za-z0-9_-]{43}$/.test(linkKey)) return gone(T.incompleteTitle, T.incompleteText);
    if (!window.crypto || !crypto.subtle) return gone(T.goneTitle, T.noCrypto);
    let info;
    try {
      const response = await fetch("/api/v1/shares/" + id);
      if (!response.ok) return gone(T.goneTitle, T.goneText);
      info = await response.json();
    } catch (_) {
      return gone(T.goneTitle, T.failed);
    }
    text($("ask-title"), T.askTitle);
    text($("ask-info"), T.askInfo + " " + availability(info));
    text($("password-label"), T.password);
    $("password-box").classList.toggle("hidden", !info.password);
    text($("show"), T.show);
    $("show").addEventListener("click", () => openShare(info));
    $("password").addEventListener("keydown", (e) => {
      if (e.key === "Enter") openShare(info);
    });
    show("ask");
    if (info.password) $("password").focus();
  }

  start();
})();
