// 2Secret: filling a login into a page. One copy for the popup (the Fill
// button) and the background worker (logins the user allowed an AI agent to
// use, which the 2Secret app sends through the native messaging host).
//
// A plain script, not a module: the worker loads it with importScripts (or,
// in Firefox, from background.scripts) and the popup with a <script> tag,
// and twosecretFill has to be a self-contained function the browser can
// serialise into the page.
(() => {
  const api = globalThis.browser ?? globalThis.chrome;

  // Is a page location allowed to receive an item's credentials? `rules` are
  // the item's registrable domains, with the https and port requirements; an
  // `exact` domain is a public suffix (github.io), whose subdomains are other
  // people's sites.
  function twosecretAllowed(loc, rules) {
    const host = (loc.hostname || "").toLowerCase().replace(/\.$/, "");
    if (!host || !/^https?:$/.test(loc.protocol)) return false;
    return rules.some((r) =>
      (host === r.domain || (!r.exact && host.endsWith("." + r.domain)))
      && (!r.https || loc.protocol === "https:")
      && (r.port === null || r.port === undefined || (loc.port || (loc.protocol === "https:" ? "443" : "80")) === String(r.port)));
  }

  // Runs inside every frame of the page (serialised by the browser, not
  // eval'd here, so it has to be self-contained and repeats the check above).
  // Each frame checks its own address, so credentials never reach a frame
  // from another site or a page the tab navigated to in the meantime.
  // Returns {outcome: "filled" | "nothing" | "mismatch", submitted}.
  function twosecretFill(username, password, code, rules, submit) {
    const allowed = (loc) => {
      const host = (loc.hostname || "").toLowerCase().replace(/\.$/, "");
      if (!host || !/^https?:$/.test(loc.protocol)) return false;
      return rules.some((r) =>
        (host === r.domain || (!r.exact && host.endsWith("." + r.domain)))
        && (!r.https || loc.protocol === "https:")
        && (r.port === null || r.port === undefined || (loc.port || (loc.protocol === "https:" ? "443" : "80")) === String(r.port)));
    };
    if (!allowed(window.location)) return { outcome: "mismatch", submitted: false };
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
    let anchor = null;
    if (password && passwords.length) {
      setValue(passwords[0], password);
      filled = true;
      anchor = passwords[0];
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
        if (!anchor) anchor = user;
      }
    }
    if (code && !passwords.length) {
      const otp = inputs.find((i) => (i.autocomplete || "") === "one-time-code")
        || inputs.find((i) => texty(i) && /otp|totp|2fa|mfa|code|token|verification/.test(hint(i)));
      if (otp) {
        setValue(otp, code);
        filled = true;
        if (!anchor) anchor = otp;
      }
    }
    let submitted = false;
    // Submitting like a person would: the form's own button, else the
    // form's submit (which runs its validation and submit handlers).
    if (filled && submit && anchor) {
      const form = anchor.form;
      if (form) {
        const button = Array.from(form.querySelectorAll('button[type="submit"], input[type="submit"], button:not([type])'))
          .find(visible);
        if (button) {
          button.click();
        } else if (typeof form.requestSubmit === "function") {
          form.requestSubmit();
        } else {
          form.submit();
        }
        submitted = true;
      }
    }
    return { outcome: filled ? "filled" : "nothing", submitted };
  }

  // The tab a login may go to: the active tab of the window used last, then
  // the active tab of any other normal window, the first whose address the
  // rules allow. Never a tab the agent names, never incognito.
  async function twosecretFindTab(rules) {
    const candidates = [];
    try {
      const win = await api.windows.getLastFocused({ populate: true, windowTypes: ["normal"] });
      if (win && win.tabs) candidates.push(...win.tabs.filter((t) => t.active));
    } catch (e) {
      // No window of that kind.
    }
    for (const tab of await api.tabs.query({ active: true })) {
      if (!candidates.some((c) => c.id === tab.id)) candidates.push(tab);
    }
    for (const tab of candidates) {
      if (tab.id === undefined || !tab.url || tab.incognito) continue;
      try {
        if (twosecretAllowed(new URL(tab.url), rules)) return tab;
      } catch (e) {
        // Not a web address.
      }
    }
    return null;
  }

  // A login the 2Secret app sends (the user allowed an agent to use it):
  // fill the matching active tab and report {id, outcome, submitted}, where
  // outcome is filled, nothing (a tab, but no fields) or no_tab.
  async function twosecretHandleFill(cmd) {
    const rules = Array.isArray(cmd.rules) ? cmd.rules : [];
    const tab = await twosecretFindTab(rules);
    if (!tab) return { id: cmd.id, outcome: "no_tab", submitted: false };
    let results;
    try {
      results = await api.scripting.executeScript({
        target: { tabId: tab.id, allFrames: true },
        func: twosecretFill,
        args: [cmd.username || "", cmd.password || "", cmd.code || "", rules, cmd.submit !== false],
      });
    } catch (e) {
      // A page scripts may not run in.
      return { id: cmd.id, outcome: "no_tab", submitted: false };
    }
    const outcomes = results.map((r) => r && r.result).filter((r) => r && typeof r === "object");
    const filled = outcomes.find((o) => o.outcome === "filled");
    if (filled) return { id: cmd.id, outcome: "filled", submitted: !!filled.submitted };
    return { id: cmd.id, outcome: outcomes.some((o) => o.outcome === "nothing") ? "nothing" : "no_tab", submitted: false };
  }

  globalThis.twosecretAllowed = twosecretAllowed;
  globalThis.twosecretFill = twosecretFill;
  globalThis.twosecretFindTab = twosecretFindTab;
  globalThis.twosecretHandleFill = twosecretHandleFill;
})();
