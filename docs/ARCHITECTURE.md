# Architecture

```
                ┌───────────────────────────── one Rust codebase ─────────────────────────────┐
                │                                                                              │
  Desktop (macOS, Windows, Linux, BSD) ─┐                                                      │
  iOS ──────────────────────────────────┤  crates/app   (Dioxus UI, platform layer)            │
  Web vault (WebAssembly) ──────────────┤        │                                             │
  Browser extension (WebAssembly) ──────┘        │                                             │
                                                 ▼                                             │
  crates/cli  ──────────────────────────►  crates/client  (HTTP + sync engine, native + wasm)  │
                                                 │                                             │
                                                 ▼                                             │
                                          crates/core     (crypto, model, sync merge, …)       │
                │                                                                              │
                └──────────────────────────────────────────────────────────────────────────────┘
                                                 │ HTTPS, encrypted payloads only
                                                 ▼
                                          crates/server   (axum + SQLite, serves the web vault)
```

## Crates

### `twosecret-core`

Pure Rust, no I/O except an optional file storage backend. Compiles for every
target including `wasm32-unknown-unknown`.

| Module | Responsibility |
|---|---|
| `crypto` | Argon2id, HKDF, XChaCha20-Poly1305, X25519 sealed boxes, Secret Key, keysets, wrapped keys, password envelopes |
| `item` | Item model: 19 categories with templates, fields, URLs, tags, attachments, password history |
| `profile` | On-disk representation (fully encrypted) and device secrets |
| `session` | An unlocked account: decrypted vaults/items, CRUD, vault management, password change |
| `sync` | Building sync requests and merging responses, conflict resolution |
| `api` | Shared DTOs of the HTTP API |
| `generator`, `wordlist`, `strength` | Password/passphrase/PIN generator, EFF wordlist, zxcvbn strength |
| `totp` | RFC 6238 TOTP, `otpauth://` parsing, Steam Guard |
| `ssh` | Ed25519 SSH key generation (OpenSSH format) for SSH Key items |
| `watchtower` | Security audit and Have I Been Pwned k-anonymity helpers |
| `import`, `export` | 1Password, Bitwarden, KeePass, CSV importers; JSON/CSV/encrypted export |
| `secret_ref` | `2s://` references, template injection |
| `agent` | Agent Access: the socket protocol, agent identity (Ed25519), consent (`Ask`, grants, the encrypted store and log) and running requests against a `Session` |
| `emergency_kit` | Printable Emergency Kit |
| `storage` | Key/value storage trait, file and memory backends |

### `twosecret-client`

`Client` wraps every API endpoint. `flows` implements user-level operations
(sign up, sign in, connect, sync, share, change password, breach check).
`sync_with` borrows the session only for short synchronous steps, so the UI
remains responsive while syncing; edits made during a sync are detected and
uploaded in the next round.

### `twosecret-server`

axum + SQLite (bundled). Stateless request handlers on top of a single
connection (WAL mode) used through `spawn_blocking`.

### `twosecret-cli`

The `2secret` binary (clap). Session caching for shells, clipboard helper
process, secret references, `2secret mcp`.

### `twosecret-agent`

Agent Access for AI tools: the Model Context Protocol server (JSON-RPC 2.0
over stdin/stdout, written by hand) with its tools, the client of the desktop
app's socket (`access.sock`, a named pipe on Windows), one Ed25519 key per AI
tool, and the filter that replaces secrets by their `2s://` references in a
program's output. Used by the CLI. It also holds the browser side of agentic
autofill: the native messaging host loop (`host`, run by the desktop app when
a browser starts it, 4-byte-length frames on stdin/stdout, connected to the
app as role `browser`) and where each browser looks for the host manifest
(`native_host`). See [AGENTS.md](AGENTS.md).

### `twosecret-app`

Dioxus 0.7 app with features `desktop`, `web`, `mobile` and `extension`.
`platform.rs` contains the few platform-specific pieces (storage, timers,
background work, clipboard, downloads); `extension.rs` the browser-extension
bridge; `agent_access.rs` the socket for AI agents and browsers with the
consent flow, `fill_queue.rs` the logins waiting for a browser, and
`native_host.rs` the host registration per browser and the host mode of the
binary; `components/` the UI; `i18n.rs` English and Dutch strings.

## HTTP API (`/api/v1`)

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /health` | – | Version and sign-up mode |
| `POST /prelogin` | – | Salt and KDF parameters for an e-mail address |
| `POST /register` | – | Create an account (auth key, encrypted keyset, public key) |
| `POST /login` | – | Exchange an auth key for a session token |
| `POST /logout` | ✓ | End this session |
| `GET/PUT/DELETE /account` | ✓ | Account info, rename, delete |
| `POST /account/password` | ✓ | Change master password (new salt, auth key, keyset) |
| `PUT /account/avatar` | ✓ | Set or remove the profile photo (encrypted with the account key; returned by `GET /account` and at sign-in) |
| `GET /devices`, `DELETE /devices/{id}` | ✓ | List and revoke sessions |
| `GET /users/lookup?email=` | ✓ | Public key of another user (for sharing) |
| `GET/POST /vaults` | ✓ | List vaults, create a vault |
| `PUT/DELETE /vaults/{id}` | ✓ | Rename (manager+), delete (owner) or leave |
| `GET/POST /vaults/{id}/members` | ✓ | List members, share (manager+) |
| `PUT/DELETE /vaults/{id}/members/{account}` | ✓ | Change role, revoke |
| `POST /sync` | ✓ | Upload changes and download everything newer |

### Sync protocol

Each vault has a revision counter on the server. A sync request contains, per
vault, the highest revision the client has merged (`since`) and its local
changes (`id`, `base_revision`, encrypted `data` or `null` for deletion). For
each change the server checks `base_revision` against the stored revision:

- equal → accepted, the vault counter increments and the item gets the new revision;
- different → returned as a conflict with the server's current version.

The response lists all accessible vaults (so new shares appear and revoked
ones disappear) and every item changed after `since`. Clients resolve
conflicts (newest edit wins; the other version's password is kept in the
password history) and repeat until nothing is pending.

## Storage on devices

| Platform | Location |
|---|---|
| Linux / BSD | `$XDG_DATA_HOME/2secret` or `~/.local/share/2secret` |
| macOS / iOS | `~/Library/Application Support/2Secret` |
| Windows | `%APPDATA%\2Secret` |
| Web / extension | IndexedDB database `2secret` (object store `kv`: `profile`, `device`, `prefs`) |

`TWOSECRET_HOME` overrides the directory on desktop and CLI. Besides the
profile and device secrets the desktop apps keep `prefs.json` (unencrypted
preferences), `biometric.json`, `agents.json` (agents, permissions and log,
encrypted with the account key), the SSH agent's `agent.sock` and Agent
Access's `access.sock`; `2secret mcp` keeps `agent-key-<tool>.json`, the
browser connection `agent-key-browser-<browser>.json` (and on Windows the
host manifests under `native-host/`).
