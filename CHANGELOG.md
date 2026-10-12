# Changelog

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
