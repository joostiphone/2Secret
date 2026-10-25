# Privacy answers and permission justifications for the stores

**Single purpose:** a password manager: fill logins, one-time codes and
passkeys from the user's end-to-end encrypted 2Secret vault.

**Data collected:** none. The extension sends nothing to the developer. The
vault is encrypted on the device; it only talks to the sync server the user
chose (2secret.app or their own) and, with the desktop app, to that app on
the same computer. No analytics, no advertising, no third-party code.

**Permission justifications**

- `activeTab`, `scripting`: fill the user name, password or one-time code
  into the page the user is on, only when the user clicks *Fill* (or allows
  an AI agent's request in the desktop app), and only into pages that belong
  to the item's website.
- `storage`: keep the vault's encrypted data and settings in the browser;
  `storage.session` keeps the unlocked key until the browser closes or the
  auto-lock time passes.
- `clipboardWrite`: copy a password or code when the user asks.
- `nativeMessaging`: talk to the 2Secret desktop app on the same computer.
  The app hands the extension a login that the user has just allowed an AI
  agent to use, so 2Secret can sign the user in without the agent seeing the
  password. The extension never reads the vault of the app; it only receives
  what the user allowed, one login at a time.
- `alarms`: reconnect to the desktop app after the browser or the
  extension's background restarted.
- Host permission `<all_urls>`: logins exist for any website; filling is
  still limited to the active tab that belongs to the item's website, after
  a click or an approval.
- Content scripts on `https://*/*` and `http://localhost/*`: offer the
  vault's passkeys when a page asks for one (WebAuthn); the page can only
  ask, and 2Secret opens a window for the user to decide.

**Remote code:** none. All code ships in the package.
