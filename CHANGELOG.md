# Changelog

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
