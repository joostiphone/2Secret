// Runs in the page itself (MAIN world) of top-level https pages. It only wraps
// navigator.credentials.create() and .get() for passkeys (WebAuthn): the
// request goes to 2Secret, which asks the user, and anything 2Secret does not
// handle goes to the browser's own implementation. It reads nothing else.
(() => {
  "use strict";
  const creds = navigator.credentials;
  if (!creds || typeof PublicKeyCredential === "undefined" || window.top !== window) return;

  const CHANNEL = "2secret-passkey";
  const ES256 = -7;
  const nativeCreate = creds.create.bind(creds);
  const nativeGet = creds.get.bind(creds);

  const bytes = (src) =>
    src instanceof ArrayBuffer ? new Uint8Array(src) : new Uint8Array(src.buffer, src.byteOffset, src.byteLength);
  const b64u = (src) => {
    let s = "";
    for (const b of bytes(src)) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const unb64u = (s) => {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  };
  const notAllowed = () =>
    new DOMException("The operation either timed out or was not allowed.", "NotAllowedError");

  let counter = 0;
  function ask(kind, options, signal) {
    return new Promise((resolve, reject) => {
      const id = `${Date.now().toString(36)}-${++counter}-${Math.random().toString(36).slice(2)}`;
      const done = () => window.removeEventListener("message", onMessage);
      const onMessage = (e) => {
        const d = e.data;
        if (e.source !== window || !d || d.channel !== CHANNEL || d.direction !== "to-page" || d.id !== id) return;
        done();
        resolve(d);
      };
      window.addEventListener("message", onMessage);
      if (signal) {
        if (signal.aborted) return reject(signal.reason);
        signal.addEventListener("abort", () => { done(); reject(signal.reason); }, { once: true });
      }
      window.postMessage({ channel: CHANNEL, direction: "to-extension", id, kind, options }, window.location.origin);
    });
  }

  // Own properties shadow the native getters, so the objects work with
  // `instanceof` checks as well as with libraries that read the fields.
  function credential(r, response, json) {
    const cred = {
      id: r.credential_id,
      rawId: unb64u(r.credential_id),
      type: "public-key",
      authenticatorAttachment: "cross-platform",
      response,
      getClientExtensionResults: () => ({}),
      toJSON: () => json,
    };
    Object.setPrototypeOf(cred, PublicKeyCredential.prototype);
    return cred;
  }

  function registration(r) {
    const response = {
      clientDataJSON: unb64u(r.client_data_json),
      attestationObject: unb64u(r.attestation_object),
      getAuthenticatorData: () => unb64u(r.authenticator_data),
      getPublicKey: () => unb64u(r.public_key),
      getPublicKeyAlgorithm: () => r.algorithm,
      getTransports: () => ["internal", "hybrid"],
    };
    Object.setPrototypeOf(response, AuthenticatorAttestationResponse.prototype);
    return credential(r, response, {
      id: r.credential_id,
      rawId: r.credential_id,
      type: "public-key",
      authenticatorAttachment: "cross-platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: r.client_data_json,
        attestationObject: r.attestation_object,
        authenticatorData: r.authenticator_data,
        publicKey: r.public_key,
        publicKeyAlgorithm: r.algorithm,
        transports: ["internal", "hybrid"],
      },
    });
  }

  function assertion(r) {
    const response = {
      clientDataJSON: unb64u(r.client_data_json),
      authenticatorData: unb64u(r.authenticator_data),
      signature: unb64u(r.signature),
      userHandle: unb64u(r.user_handle),
    };
    Object.setPrototypeOf(response, AuthenticatorAssertionResponse.prototype);
    return credential(r, response, {
      id: r.credential_id,
      rawId: r.credential_id,
      type: "public-key",
      authenticatorAttachment: "cross-platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: r.client_data_json,
        authenticatorData: r.authenticator_data,
        signature: r.signature,
        userHandle: r.user_handle,
      },
    });
  }

  creds.create = async function create(options) {
    const pk = options && options.publicKey;
    const algs = pk && (pk.pubKeyCredParams || []).map((p) => p.alg);
    if (!pk || (algs.length && !algs.includes(ES256))) return nativeCreate(options);
    let request;
    try {
      request = {
        rp_id: pk.rp && pk.rp.id ? String(pk.rp.id) : null,
        rp_name: pk.rp && pk.rp.name ? String(pk.rp.name) : "",
        user_handle: b64u(pk.user.id),
        user_name: String(pk.user.name || ""),
        user_display_name: String(pk.user.displayName || ""),
        challenge: b64u(pk.challenge),
        algorithms: algs,
        exclude_credentials: (pk.excludeCredentials || []).map((c) => b64u(c.id)),
      };
    } catch (e) {
      return nativeCreate(options);
    }
    const answer = await ask("create", request, options.signal);
    if (answer.result) return registration(answer.result);
    if (answer.fallback) return nativeCreate(options);
    throw answer.error === "InvalidStateError"
      ? new DOMException("A passkey for this account already exists.", "InvalidStateError")
      : notAllowed();
  };

  creds.get = async function get(options) {
    const pk = options && options.publicKey;
    // Passkey suggestions in the username field stay with the browser.
    if (!pk || options.mediation === "conditional") return nativeGet(options);
    let request;
    try {
      request = {
        rp_id: pk.rpId ? String(pk.rpId) : null,
        challenge: b64u(pk.challenge),
        allow_credentials: (pk.allowCredentials || []).map((c) => b64u(c.id)),
      };
    } catch (e) {
      return nativeGet(options);
    }
    const answer = await ask("get", request, options.signal);
    if (answer.result) return assertion(answer.result);
    if (answer.fallback) return nativeGet(options);
    throw notAllowed();
  };
})();
