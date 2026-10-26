# Changelog

## 1.11.1

- **AutoFill on the Mac and iPhone in 2Secret's own look**: the panel that
  opens when you fill a password, passkey or verification code now has the
  app's logo, colours and theme (light, dark or system, as set in 2Secret),
  shows the website it is for, and lists logins with their website icons.
  The Touch ID and Face ID dialog says what happens ("2Secret is trying to
  unlock your vault for github.com") instead of "fill with 2Secret". A Touch
  ID given a moment ago is reused for a few minutes when the system keeps the
  extension running, so two fills in a row ask once.

## 1.11.0

**Agent Access, part two**: an AI agent in your browser gets signed in by
2Secret, without ever seeing the password.

- **Sign in for an agent** (`fill_login`). An AI agent that works in your
  browser (Claude for Chrome, Perplexity Comet, ChatGPT Atlas, a browser
  driven by Playwright or Browser Use) asks 2Secret to sign in with an item
  on the page it has open. 2Secret asks you ("Claude wants to sign in to
  github.com with “GitHub” in Chrome"), with the same choices as for other
  requests and the optional Touch ID, Face ID or Windows Hello question.
  After *Allow* the browser extension fills the sign-in page that is the
  active tab (only a tab that belongs to the item's website, never one the
  agent names) and submits it. The agent only hears that it was filled, or
  why not. Logged as *fill in the browser*.
- **Browser connection** (*Settings → Desktop app → Browser connection*):
  one button sets the extension up to talk to the app in Chrome, Chromium,
  Brave, Microsoft Edge, Vivaldi, Arc and Firefox on macOS, Windows and
  Linux. 2Secret itself is the browser's native messaging host; the app
  only accepts that connection from its own program, and the browser can do
  nothing but wait for the logins you allow. The connected browsers are
  listed with the agents and can be revoked there.
- **Browser extension 1.11**: connects to the app when it is set up
  (permissions `nativeMessaging` and `alarms`), one copy of the fill code for
  the popup and the background, and a fixed id for the store and unpacked
  builds alike. The Fill button is unchanged and still never submits.
- Command line: `2secret agent status` also shows which browsers are set up;
  `agent_status` lists the connected browsers.
- Windows: the app no longer builds as a console program.
- Documentation: *Filling a login in your browser* in `docs/AGENTS.md`,
  `docs/EXTENSION.md` (building, ids, publishing in the stores),
  `docs/SECURITY.md`.

## 1.10.0

**Agent Access**: AI tools use your vault, you stay in charge.

- **AI agents in the desktop apps** (*Settings → Desktop app → AI agents*,
  off by default). Claude Code, Claude Desktop, Cursor, Codex, Gemini CLI and
  any other tool that speaks the Model Context Protocol connect through
  `2secret mcp`. The first time a tool connects 2Secret asks whether it may,
  and shows the program behind it. A connected tool can search the titles,
  user names, websites and tags of your items; it never gets a password,
  one-time code or note without asking.
- **Every secret needs your yes.** Reading a field, getting a one-time code,
  saving or changing an item: 2Secret shows which tool asks, for which item
  and fields, and why. Allow it once, for these items until 2Secret locks, or
  for these items for 8 hours. Optionally 2Secret asks for Touch ID, Face ID
  or Windows Hello first. Deny is the default; Enter and Escape refuse.
- **Programs get secrets, the model does not.** The tool can run a program
  with `2s://` references in its environment (`run_command`): 2Secret asks
  once for all of them, the program gets the values, and in the output the
  tool reads the values are replaced by their references. A new login can be
  saved with a password 2Secret generates, so the tool never sees it.
- **Agents, permissions and a log** in the settings: which tools are
  connected (each with its own key), what they may do without asking, and
  every request with your answer. Revoke a tool there. Everything is
  encrypted with your account key and forgotten from memory when 2Secret
  locks, when open questions are refused.
- Command line: `2secret mcp` (and `--standalone` for use without the app:
  only searching and generating), `2secret agent status`. New crate
  `twosecret-agent`. See `docs/AGENTS.md`.

## 1.9.4

Security improvements from a review of the cryptography against a stolen
server database, a stolen device and a hostile server.

- **Known keys.** The apps and the command line remember the public keys of
  everyone you sealed a vault key to (sharing a vault, replacing its key,
  an emergency contact). When the server later reports other keys for that
  person, nothing is sent to them and the app shows both fingerprints; you
  can trust the new keys after comparing them (`2secret account trust-keys`
  on the command line). Until now a server could put its own keys in
  someone's place, for an emergency contact even without you doing
  anything.
- **Replaced vault keys.** A vault key that the server offers sealed to
  your public key for a vault without other members is refused: only your
  own devices could replace that key, and they do so with your account
  key. Every replaced or refused key is mentioned after the sync.
- **Mac: the Touch ID key is in the protected keychain.** The key that
  unlocks 2Secret with Touch ID was in the login keychain, which has no
  Touch ID protection of its own, so a copy of the Mac's disk opened with
  the login password alone. It is now a keychain item that the Secure
  Enclave releases only after Touch ID with the enrolled fingers, on this
  Mac, like on the iPhone. The app moves the key on the next unlock. (On
  the iPhone the key was already protected this way; if that protection
  cannot be set up, the key is now not stored at all.)
- Server: the database keeps a hash of each share link's proof instead of
  the proof itself, so a copy of the database can neither open a link nor
  use up its views. Links made before this version keep working.
- Server: the per-address count of failed sign-ins is forgotten after its
  window, like the other limits.
- `docs/SECURITY.md` says more precisely what the server stores and which
  limits apply.
- Dependencies: tokio 1.54.1 (RUSTSEC-2026-0386), clipboard-win 5.4.3. The
  advisory on crypto-bigint 0.5 (RUSTSEC-2026-0387, timing variability in
  P-256 arithmetic) waits for ssh-key 0.7; P-256 only signs on the device,
  after a click or consent (see `deny.toml`).
- The iOS simulator check looks for the app's process directly instead of
  asking `launchctl`, which once took too long on a busy runner.

## 1.9.3

A new look on phones, and the iPhone app fills iPhone Duo.

- **Phones** (the iPhone and Android apps, the web vault on a phone): the
  Dashboard, Items and Watchtower are in a floating tab bar of glass at the
  bottom of the screen, with a search button beside it, in the style of
  Liquid Glass in iOS 26. The buttons at the top are glass too, and the
  content scrolls on under the tab bar, the status bar and the Dynamic
  Island, which blur it softly. The other sections stay in the menu.
- iPhone: the status bar is light or dark with the app's theme, also when
  the iPhone's own setting differs, and dialogs stay clear of the Dynamic
  Island and the home indicator.
- **Menus on items and vaults**: a long press (phones, tablets) or a right
  click (computers) on an item gives its menu: copy the username, password
  or one-time password, favorite, edit, rename, move, duplicate, share via
  link, select, move to the trash. A vault in the menu has one too: a new
  item in it, edit, share, delete or leave.
- **Several items at once**: select items (the select button above the
  list, *Select* in an item's menu, or Ctrl/Cmd+click) to favorite, move
  or trash them together, or in the trash to restore or delete them.
- Search shows your favorites first, then the items with the words in
  their title (the apps, Quick Access and `2secret list`).
- The menu's categories, vaults and tags fold away with a tap on their
  heading; tags start folded.
- Website icons: *Fetch for all logins* goes on when you leave Settings and
  shows how far it is. It asks several websites at a time, each once for
  all its logins, tries the main domain for a login on a subdomain, takes
  sharper icons and scales down those over 24 KB instead of skipping them.
- **iPhone Duo**: 2Secret fills the whole screen, open and closed. Until
  now iPhone Duo showed it at the size of a regular iPhone. Open, the list
  and the item show side by side with the fold between them.
- The iPhone and iPad app is built with Xcode 27.1 and starts with the
  scene life cycle that iOS 27 asks of apps.

## 1.9.2

Security fixes from a review of the apps, the server and the way releases
are made.

- iPhone and iPad: the Secret Key is no longer included in iCloud and
  computer backups, so a backup never holds it next to the encrypted vault.
- AutoFill (iPhone, iPad, Mac) and the browser extension: on websites where
  everyone gets a subdomain of their own (such as `github.io`), a login is
  only offered on its own site, never on someone else's.
- The apps connect to a sync server only over `https://` (plain `http://`
  only to a server on the same device).
- A vault never goes back to a key it had before, so a server cannot give a
  removed member access to new items again.
- Copied passwords stay out of Windows' clipboard history and cloud
  clipboard, and out of clipboard managers on Linux and macOS.
- Website icons are fetched from public websites only, also when an address
  is an IP address written in a short form.
- The server checks the encrypted data it stores, so one account cannot
  disrupt syncing for others, limits sign-in attempts and password checks
  per address, and removes invisible characters from names.
- Updated libraries: rustls, the import of zip and XML files, and SQLite
  3.53.2 in the server.
- Every release's `SHA256SUMS` is signed (`SHA256SUMS.sig`), so downloads
  that do not update themselves can be checked: see *Checking a download*
  in `docs/UPDATES.md`.

For people who run their own server:

- The invite codes of the examples (`change-me…`) no longer let anyone sign
  up: choose your own.
- `install.sh` reads the client's address from `CF-Connecting-IP` only with
  a Cloudflare Tunnel; set `--ip-header` for another proxy.

## 1.9.1

- **Foldables and medium screens** (the inner display of iPhone Duo, tablets
  in portrait, small windows): the list and the item show side by side, at
  equal widths so the fold falls between them; on a foldable that reports its
  fold, the split is right at the fold. The menu opens next to the list.
- iPhone and iPad: the app keeps clear of the status bar, camera and home
  indicator on every side, also in landscape.
- Phones and tablets: the menu, buttons and other things you tap are at least
  44 points high, so they are easy to hit with a finger.

## 1.9.0

- **Quick Access** on the desktop: press Ctrl+Shift+Space (⇧⌘Space on the
  Mac) anywhere to find an item and copy its password (Enter), user name
  (Shift+Enter) or one-time code (Ctrl/⌘+Enter) without opening 2Secret;
  Alt/⌥+Enter shows the item in 2Secret. It is also in the menu of the icon
  in the menu bar or system tray. Under Wayland, where apps cannot register a
  shortcut, set one in the desktop's settings that runs `2-secret
  --quick-access`. *Settings → Desktop app* turns it off.
- **Start at login** (*Settings → Desktop app*): 2Secret starts in the menu
  bar or system tray when you log in, without its window.
- Linux: what 2Secret copies stays on the clipboard also without a
  clipboard manager (until it is cleared after the time you chose).
- *Settings → Desktop app* holds the icon, starting at login and Quick
  Access.
- **Scan a QR code from the screen** (desktop): *Scan QR code* in the item
  editor sets up a one-time password from the QR code a website shows for
  two-step verification, and fills in the title and user name of a new item.
  2Secret hides its window for a moment and reads the screens; the
  screenshot never leaves memory. macOS asks once for permission to record
  the screen, Wayland desktops may ask too.
- **SSH agent** (desktop, *Settings → Desktop app*): `ssh`, `git` and other
  programs log in and sign with the keys of SSH Key items (Ed25519, ECDSA,
  RSA; also passphrase-protected OpenSSH keys and RSA keys in PEM). 2Secret
  asks every time, naming the program and the key, or once per key until it
  locks; the private keys never leave 2Secret. On macOS and Linux point
  `IdentityAgent` in `~/.ssh/config` at the socket shown in the settings; on
  Windows it is the agent of the OpenSSH client of Windows (stop the
  *OpenSSH Authentication Agent* service).
- **Share via link** (all apps and `2secret share`): share an item, or the
  fields of it you pick, with someone without 2Secret. They open the link in
  any browser; it is end-to-end encrypted with a key that only the link
  holds, works for 1 hour to 30 days, can be limited to 1, 3 or 10 views and
  can ask for a password you send another way. *Settings → Sync* lists your
  links and revokes them (`2secret shares`). Needs a sync server with this
  version.
- **Emergency access** (all apps, `2secret emergency`): trust people on the
  same server with read access to the vaults you own, for when you cannot
  give it yourself. They ask for it and get it after the waiting period you
  chose (1 to 30 days in the apps) unless you deny it; you can also approve
  at once. Your apps show the request. Ending the access gives the vaults new
  keys. Needs a sync server with this version.
- CLI: a password prompt no longer asks again forever when there is no input
  left.
- Desktop: while its window is hidden in the menu bar or system tray, 2Secret
  no longer pauses at its next screen update (the window draws nothing
  then), so Quick Access, syncing and locking keep working.

## 1.8.0

- 2Secret has an icon in the menu bar (macOS) or the system tray (Windows,
  Linux). Its menu opens 2Secret, locks the vault or quits; on Windows a click
  on the icon opens 2Secret too. Closing the window keeps 2Secret running
  there, and it still locks after the auto-lock time. *Settings → Appearance*
  turns the icon off, and closing the window then quits 2Secret as before.
  Linux shows the icon through AppIndicator (on GNOME the AppIndicator
  extension); the `.deb` and `.rpm` now install its library.
- Starting 2Secret while it already runs brings its window to the front
  instead of opening a second 2Secret (Windows, Linux; macOS did this
  already), also when the window is hidden in the system tray.
- A field you add to an item with the kind *Password* gets *Generate
  password*, *Password rules* and the strength meter too, like the item's
  own password.

## 1.7.1

- Windows: 2Secret comes as one setup (`2Secret_<version>_x64-setup.exe`)
  from now on, no longer also as an `.msi`. The setup installs 2Secret for
  your user, without administrator rights, and can update itself. The `.msi`
  installed 2Secret for everyone in *Program Files*, and the two did not
  replace each other, so you could end up with two copies. When the `.msi`
  version (up to 1.7.0) is installed, the setup offers to remove it, so one
  2Secret is left; Windows asks for permission, and your vault stays where it
  is. *Download* under *Settings → Updates* in the `.msi` version gets this
  setup.

## 1.7.0

- Password rules per password: next to *Generate password* in the item
  editor, *Password rules* sets how that password is made: random,
  memorable or a PIN, its length (also exactly, from 4 to 128 characters),
  and upper case, lower case, digits, symbols and look-alike characters.
  Every change makes a new password right away. The item keeps the rules,
  encrypted and synced, so the next new password for it follows them too;
  *Use as default* makes them the generator's defaults. Versions before this
  one keep the password but forget its rules when they save the item.
- The password generator takes an exact length next to its slider.

## 1.6.3

- *Settings → About* shows where 2Secret is installed, and on Windows
  whether it is the setup for your user (which can update itself) or the
  MSI for everyone on the PC. The two install into different folders, so
  installing the MSI next to the setup leaves the setup's version as it was.

## 1.6.2

- Windows Hello: turning it on (or unlocking with it) could fail with error
  0x80098044. Windows opened its prompt behind 2Secret, and a face confirmed
  there after a few seconds no longer counted. 2Secret now brings the prompt
  to the front, and asks once more when Windows still turns it down.

## 1.6.1

- Setup links on Windows, Linux and the BSDs: `otpauth://` links on websites
  open 2Secret too, which adds the one-time password to a login. 2Secret
  registers itself for them for your user when no other app opens them;
  *Settings → Security → Setup links for one-time passwords* makes 2Secret
  the app for them. A link opened while 2Secret runs goes to that window.

## 1.6.0

- Verification codes in AutoFill: on iPhone and iPad with iOS 18 and on the
  Mac with macOS 15, Safari and other apps fill one-time codes from 2Secret
  after Face ID or Touch ID, from the logins that have a one-time password.
  *Settings → General → AutoFill & Passwords* then lists 2Secret for
  "Passkeys, passwords and codes" (if it does not after updating, turn
  2Secret off and on there once). Open 2Secret once after updating, so
  AutoFill gets the one-time passwords.
- Setting up codes: 2Secret can be chosen under *Set Up Codes In* in the same
  settings. Setup links (`otpauth://`) on websites and QR codes scanned with
  the camera then open 2Secret, which adds the one-time password to the login
  you choose or starts a new login with it.

## 1.5.1

- Dashboard: the apps open with an overview after unlocking: a greeting,
  search, the number of items, favourites and vaults, the Watchtower score
  with breached, weak and reused passwords, your favourites, recent changes,
  the vaults and the categories. It shows no passwords or other secrets.
  *Settings → Appearance → Start screen* chooses what you see after
  unlocking: the dashboard, all items, favourites or Watchtower. The browser
  extension keeps opening with the list, which suggests logins for the open
  website.
- iPhone and iPad: after typing the master password the app no longer stays
  shifted up under the status bar (iOS left the page scrolled when the
  keyboard closed), the app fits above the keyboard while you type, and text
  fields no longer zoom in when you tap them.

## 1.5.0

- AutoFill on the Mac: Safari and other apps fill passwords and sign in with
  passkeys from 2Secret after Touch ID, without a browser extension, like on
  iPhone and iPad. Turn on unlocking with Touch ID in 2Secret, then 2Secret
  in *System Settings → General → AutoFill & Passwords*. Needs macOS 14 and a
  release signed with a Developer ID: the release workflow then adds the
  extension (`macos/`) with Developer ID provisioning profiles from the App
  Store Connect API, and can notarize with that API key instead of an Apple
  ID. *Settings → Security* says where to turn AutoFill on (also on iOS).
- The macOS app is signed with a Developer ID and notarized by Apple, so it
  opens without allowing it under *Privacy & Security* first (once Apple has
  notarized it: the first submissions of a new developer account can take
  Apple days, and the release no longer waits for that). macOS may ask once
  for your login password to let the new version use its keychain item for
  Touch ID unlock; choose *Always Allow*.
- Profiles: the apps keep up to two accounts side by side, for example your
  own and one for work on another server. Switch at the top of the sidebar
  or on the lock screen; the profile you leave stays unlocked in the
  background until the app locks, which locks both. Each profile has its own
  Secret Key and its own biometric unlock. Not in the web vault or the
  browser extension. On iOS and macOS AutoFill fills from the profile that
  last wrote its logins with biometric unlock on.
- Website icons: logins show the icon of their website. The apps fetch it
  straight from the website when you save a login (over HTTPS, public host
  names only, no icon service) and keep it encrypted with the login, so
  other devices, the web vault and the browser extension show it too.
  *Settings → Appearance → Website icons* turns it off and fetches icons for
  the logins you already have.
- Profile photo: *Settings → Account → Add photo*. The app makes a small
  square picture of it, encrypts it with your account key and syncs it to
  your other devices through the new `PUT /account/avatar` (servers from
  this version; with an older server it stays on the device).
- Vault icons: choose an icon when creating or editing a vault. It is part
  of the vault's encrypted details, so everyone with access sees it.
- Links in the app (an item's websites, *What's new*, the project page) open
  in the browser on macOS, iOS and Linux; clicking them did nothing there.
- Browser extension: a new passkey is stored before its window closes. The
  window could close first, and then the website had the passkey but 2Secret
  did not.
- Server: the limits forget client addresses and e-mail addresses as soon as
  their window has passed (a day for sign-ups, 15 minutes for failed
  sign-ins), instead of when the server restarts.
- `deploy/proxmox/install.sh` keeps the journal for 14 days.

## 1.4.2

- The 2Secret server `sync.2secret.app` runs: the apps offer it again, and
  it is the default when creating an account, signing in or connecting.
- Server: `--trusted-proxies` (`TWOSECRET_TRUSTED_PROXIES`) believes the
  client address header from reverse proxies on other machines, such as
  cloudflared in another container, so limits per address keep working.
  `deploy/proxmox/install.sh` has `--listen` and `--trusted-proxy` for it.

## 1.4.1

- The apps offer the 2Secret server (`sync.2secret.app`) once it runs. Until
  then a new account is kept *only on this device* by default, and signing in
  or connecting asks for your own server's address.

## 1.4.0

- The 2Secret server: when creating an account, signing in or connecting,
  choose *2Secret server* (`sync.2secret.app`, nothing to set up), *your own
  server* or *only on this device*.
- Backups: *Settings → Backup & export* shows when you last made a backup on
  this device, and 2Secret reminds you now and then (every month by default,
  adjustable) to make an encrypted backup of all vaults, so you keep your data
  even if a device or server is lost for good.
- Server limits for servers that are open to everyone: storage per account
  (what does not fit stays on the device, nothing is lost), new accounts per
  address per day, a maximum number of accounts, and the client's address
  from a local proxy (`--account-storage-mb`, `--signups-per-ip`,
  `--max-accounts`, `--client-ip-header`). The apps show your storage use.
- `deploy/proxmox`: creates a Proxmox LXC container with the server, a
  Cloudflare Tunnel, nightly database backups and signed automatic updates
  (docs/PUBLIC-SERVER.md). Releases now also list the server and web vault in
  the signed `update.json`.

## 1.3.0

- Updates from within the app (*Settings → Updates*), off by default. On
  Windows (setup installation), macOS and the Linux AppImage, 2Secret can
  install new versions itself when it starts; elsewhere, including Android,
  it says when a new version is available and opens the download. Only
  updates signed with 2Secret's key, for a newer version and with the signed
  SHA-256 are installed (docs/UPDATES.md).

## 1.2.0

- iOS AutoFill: fill passwords and sign in with passkeys in Safari and apps,
  after Face ID or Touch ID (needs *Unlock with Face ID* in the app).
- The iOS app can be published on the App Store: an Xcode project with the
  AutoFill extension (`ios/`), store texts and screenshots in English and
  Dutch, and automatic uploads to TestFlight (see docs/APP-STORE.md).
- Android app (Android 7 and newer), attached to releases as a signed `.apk`
  and an `.aab` for app stores. Its data stays out of Android's cloud backups.
- Passkeys: the browser extension offers to save new passkeys in 2Secret and
  signs in with them; you can always choose another device or security key
  instead. Passkeys are end-to-end encrypted and sync with the vault, and
  can be imported from Bitwarden. Firefox 128 or newer is needed.
- Unlock with Touch ID (macOS), Face ID or Touch ID (iOS) and Windows Hello
  (*Settings → Security*). The master password is still needed every 14 days.
- Removing someone from a shared vault gives the vault a new key: everything
  is re-encrypted, so what is added or changed afterwards is unreadable with
  the key they had. Managers can also replace a vault's key themselves
  (*Share → Replace vault key*, `2secret vault rotate-key`).
- New items without a chosen vault go to your personal vault, never to a
  vault that is shared with others.
- Fresh screenshots in English and Dutch (`scripts/screenshots.sh`).

## 1.1.0

Quantum-resistant sharing:

- Vault keys shared with other people are wrapped with a hybrid of X25519 and
  ML-KEM-768 (FIPS 203), so recorded traffic or a stolen server database
  cannot be decrypted later with a quantum computer. The recipient's device
  re-wraps the key with its own 256-bit account key on its next sync.
- Accounts publish their ML-KEM public key automatically on their first sync
  with this version; their fingerprint changes once when that happens.
- New Secret Keys have 130 bits of entropy (26 random characters instead of
  25). Existing Secret Keys keep working.
- Update every device: 2Secret 1.0 cannot open a vault shared with the new
  scheme until the recipient has synced once with 1.1.

Security hardening, informed by the LastPass breaches:

- Browser extension: right before filling, the page and every frame are
  checked against the item's websites, so credentials never reach a frame
  from another site or a page the tab navigated to after the popup opened.
- Websites are matched by registrable domain using the Public Suffix List,
  `https` items are never filled into `http` pages, ports are respected.
- Master passwords need at least 12 characters and a "good" strength rating.
- Clients and servers refuse Argon2id parameters below 19 MiB / 2 passes.
- Encrypted data is padded to size classes, so the server no longer learns
  exact item sizes.

## 1.0.2

- The Docker image is also available for ARM64 (Raspberry Pi, ARM servers).
- The release workflow can sign and notarize the macOS app with an Apple
  Developer ID (see CONTRIBUTING.md); without one it stays signed ad hoc.

## 1.0.1

- macOS: separate downloads for Apple silicon and Intel Macs; the app is
  signed ad hoc, so macOS offers *Open Anyway* instead of reporting it as
  damaged, and it declares macOS 11 as the minimum version.

## 1.0.0

First release of 2Secret.

- Two-Secret Key Derivation (Argon2id + Secret Key), XChaCha20-Poly1305
  encryption, X25519 vault sharing.
- Apps for macOS, Windows, Linux, the BSDs, iOS and the web from one Rust
  codebase, in English and Dutch.
- Browser extension for Chrome, Edge, Brave and Firefox with autofill.
- `2secret` CLI with secret references (`2s://`), `run` and `inject`.
- Self-hostable zero-knowledge sync server with invite-only sign-ups.
- 19 item types, custom fields, attachments, tags, favorites, trash,
  password history.
- TOTP one-time passwords, password generator, Ed25519 SSH key generation,
  Watchtower with Have I Been Pwned breach check.
- Import from 1Password, Bitwarden, LastPass, Chrome, Firefox, Safari,
  KeePass, KeePassXC and Dashlane; encrypted and plain exports.
