# Changelog

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
