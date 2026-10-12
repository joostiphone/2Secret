# 2Secret security design

This document describes how 2Secret protects your data: what is encrypted,
with which keys, what the sync server can and cannot see, and the known
limitations. The implementation lives in
[`crates/core/src/crypto.rs`](../crates/core/src/crypto.rs) and
[`crates/core/src/session.rs`](../crates/core/src/session.rs).

## Goals and threat model

2Secret is designed so that:

1. **The server operator learns nothing useful.** Someone with full access to
   the sync server (including its database) cannot read items, vault names,
   URLs or titles, and cannot mount an offline attack on master passwords.
2. **A stolen device file is protected by the master password.** The profile
   on disk is fully encrypted; without the master password it is useless.
3. **Network attackers learn nothing.** TLS protects transport, but all
   sensitive payloads are additionally end-to-end encrypted.
4. **Members of a shared vault only get access to that vault.**

2Secret does **not** protect against malware running as your user on an
unlocked device (it can read the screen, memory and keystrokes), against a
compromised operating system or browser, or against someone who knows both
your master password and your Secret Key.

## Primitives

| Purpose | Algorithm |
|---|---|
| Password stretching | Argon2id v1.3 (default: 64 MiB, 3 iterations, 4 lanes) |
| Key derivation / separation | HKDF-SHA256 |
| Symmetric encryption | XChaCha20-Poly1305 (256-bit key, random 192-bit nonce, 128-bit tag) |
| Public-key encryption | X25519 + ML-KEM-768 (FIPS 203) hybrid + HKDF-SHA256 + XChaCha20-Poly1305 |
| Randomness | OS CSPRNG (`getrandom`; `crypto.getRandomValues` in browsers) |
| Unicode normalisation | NFKD for master passwords |

All implementations are from the RustCrypto and dalek-cryptography projects;
the most important ones (`chacha20poly1305`, `curve25519-dalek`) have had
independent audits, the ML-KEM implementation not yet. Ciphertexts are encoded as `2s1.` + base64url(nonce ‖ ciphertext ‖ tag).

## Two-Secret Key Derivation (2SKD)

When an account is created, the device generates:

- a random 16-byte **salt**, and
- a **Secret Key**: 26 random characters from a 32-symbol alphabet (130 bits)
  plus one check character, shown as `2S-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXXX`.
  Secret Keys created before version 1.1 have 25 random characters (125 bits)
  and keep working.

The Secret Key is stored only on the user's devices and in their printed
Emergency Kit. Every unlock derives two independent keys:

```
salt'   = HKDF(ikm = salt, salt = email, info = "2secret/v1/argon2-salt")
k_pw    = Argon2id(NFKD(master password), salt')
k_sk    = HKDF(ikm = Secret Key, salt = email, info = "2secret/v1/secret-key")
k       = k_pw XOR k_sk
MUK     = HKDF(k, info = "2secret/v1/master-unlock-key")     # never leaves the device
AUTH    = HKDF(k, info = "2secret/v1/auth-key")              # proves knowledge to the server
```

Because `k_sk` contributes 130 bits of entropy, the authentication key the
server sees cannot be used to brute-force the master password, even with
unlimited computing power — the attacker would also have to guess the Secret
Key. A weak master password is still protected by the Secret Key against
server-side attacks, and a stolen device (which holds the Secret Key) is
protected by Argon2id.

## Key hierarchy

```
Master Unlock Key (MUK) ─┐
                         ▼
               Account key (AK, random 256-bit)  ──►  X25519 private key
                         │                              ML-KEM-768 private key (derived)
                         │                              (public keys on server)
                         ▼
         Vault key (VK, random 256-bit, one per vault)
                         │
                         ▼
             Items and vault metadata
```

- The **account keyset** stores AK encrypted with the MUK and the X25519
  private key encrypted with AK. The ML-KEM-768 private key is not stored: it
  is derived from AK (`HKDF(AK, info = "2secret/v1/ml-kem-768/d")` and
  `".../z"` as the 64-byte FIPS 203 seed), so every device of the account has
  it. Changing the master password only re-encrypts AK; vault keys and items
  stay untouched.
- Every **vault** has its own random key. For the vault owner it is wrapped
  with AK ("symmetric" wrapping). For people the vault is shared with, it is
  wrapped to their public keys ("hybrid sealed" wrapping, see *Sharing*).
- Every **item** is serialised to JSON and encrypted with its vault key.

### Associated data

Each ciphertext is bound to its purpose and location via AEAD associated data,
so the server cannot swap ciphertexts around undetected:

| Ciphertext | Associated data |
|---|---|
| Account key | `2secret/v1/keyset/account-key` |
| Private key | `2secret/v1/keyset/private-key` |
| Vault key | `2secret/v1/vault-key/<vault id>` |
| Vault metadata (name, description) | `2secret/v1/vault-meta/<vault id>` |
| Item | `2secret/v1/item/<vault id>/<item id>` |
| Sync token (on device) | `2secret/v1/server-token/<account id>` |

An item moved by the server to another vault, or replaced by a different
item's ciphertext, fails to decrypt. The decrypted item id is also checked.

## What the server stores

| Data | Visible to the server? |
|---|---|
| E-mail address, display name | yes (needed for sign-in and sharing) |
| Salt and Argon2id parameters | yes (needed to derive keys on new devices) |
| Authentication key | only a server-side Argon2id hash of it |
| Account keyset | encrypted (account key under MUK) |
| Public keys (X25519, ML-KEM-768) | yes |
| Vault names and descriptions | **no** (encrypted) |
| Item titles, usernames, passwords, URLs, notes, files | **no** (encrypted) |
| Number of vaults/items, size class of each item (padded), modification times | yes (metadata) |
| Who shares which vault with whom, and with which role | yes |

**Unknown accounts:** the pre-login endpoint answers unknown e-mail addresses
with stable fake salts (derived from a per-installation server secret), and
failed logins for unknown addresses take as long as real ones, so the server
does not reveal whether an address has an account.

## Authentication and sessions

Signing in sends the 32-byte authentication key over TLS. The server stores
`Argon2id(auth key, random salt)` and compares in constant time. A successful
login returns a random 256-bit bearer token; the server stores only its
SHA-256. Tokens expire after 30 days of inactivity (configurable) and can be
revoked per device. Changing the master password signs out all other devices.
Failed logins are rate limited per account (10 per 15 minutes).

On the device the token is stored encrypted with the account key, so a copied
profile file cannot be used to talk to the server either.

## Sharing

To share a vault, the sharer fetches the recipient's public keys from the
server, wraps the vault key to them and uploads the wrapped key together with
a role (`viewer`, `editor`, `manager`). The server enforces roles for every
write.

### Quantum-resistant sharing

Vault keys are wrapped with a **hybrid** of X25519 and ML-KEM-768 (the NIST
post-quantum standard, FIPS 203), the same approach as Signal's PQXDH and
Apple's iMessage PQ3:

```
x_ss  = X25519(ephemeral private key, recipient X25519 public key)
pq_ss, kem_ct = ML-KEM-768.Encaps(recipient ML-KEM public key)
key   = HKDF(ikm  = pq_ss ‖ x_ss,
             salt = epk ‖ recipient X25519 pk ‖ SHA-256(recipient ML-KEM pk) ‖ SHA-256(kem_ct),
             info = "2secret/v1/hybrid-sealed-box")
wrapped vault key = XChaCha20-Poly1305(key, vault key, AD = "2secret/v1/vault-key/<vault id>")
```

An attacker has to break **both** X25519 and ML-KEM-768 to recover a vault
key, so recording shared vaults today and decrypting them with a future
quantum computer ("harvest now, decrypt later") does not work, and a flaw in
the young ML-KEM would still leave X25519's protection in place.

The hybrid ciphertext only lives on the server until the recipient's next
sync: their device then re-wraps the vault key with its own account key
(256-bit symmetric) and replaces its copy on the server. Personal and shared
vaults therefore rest on 256-bit symmetric keys only.

Accounts created with 2Secret 1.0 publish their ML-KEM public key on their
first sync with 1.1. Until a recipient has done so, vaults shared with them
fall back to X25519 alone, and their device re-wraps the key symmetrically on
its next sync as described above.

### Fingerprints

The apps show the recipient's **public key fingerprint** (e.g.
`3F9A-77C1-0B2E-91D4`), the first 8 bytes of SHA-256 over both public keys.
Comparing it out of band protects against a malicious server substituting
its own keys. A fingerprint changes once, when an account created with 1.0
publishes its ML-KEM key.

### Revocation and key rotation

Removing someone stops the server from sending them further updates, and the
vault immediately gets a **new key**: the remover's device generates a random
vault key, re-encrypts the vault name and every item with it, wraps it for
each remaining member (hybrid sealed, as above) and uploads everything in one
request. The server applies it all or nothing, and only if the vault's member
list and items still match what the client saw, so nobody is left behind and
no item stays under the old key. Whatever is added or changed afterwards is
unreadable with the key the removed person had, even with a copy of the
server database.

Each vault key has a generation number. Writes encrypted under an older
generation (from a device that was offline during the rotation) are refused;
that device receives the new key on its next sync, re-encrypts its pending
changes and sends them again, so no edit is lost. Managers can also replace
a vault's key on request, for example after someone left on their own.

What rotation cannot undo: the removed person may have kept copies of what
they could already see. Change the passwords that matter after removing
someone.

## Passkeys

Passkeys (WebAuthn credentials) are stored inside items, so their private
keys are end-to-end encrypted and synced like everything else. 2Secret acts
as a software authenticator for *synced* passkeys: ES256 (ECDSA P-256)
keys, "none" attestation, the backup-eligible and backed-up flags set, user
verification by unlocking 2Secret, and a signature counter that stays 0.

In the browser extension, a small script in top-level `https` pages wraps
`navigator.credentials.create()` and `.get()`. It reads nothing from the
page; it forwards only the WebAuthn request. 2Secret then opens its own
window, where you decide: save or use a passkey, use another device or
security key (the browser takes over), or cancel. The page's origin is taken
from the browser, never from the page, and a website can only create or use
passkeys for its own domain or a parent domain that is not a public suffix
(`alice.github.io` can never use a passkey for `github.io`). The answer goes
back only to the page that asked, and only while it is still open. Passkey
suggestions in the username field (conditional mediation) and iframes stay
with the browser. *Settings → Passkeys in this browser* turns this off.

Passkeys can be imported from Bitwarden JSON exports. `2secret get --json`
leaves passkey private keys out unless `--reveal` is given.

## Sync and conflicts

Each vault has a server-side revision counter. Clients upload changes with the
revision they were based on; stale writes are rejected as conflicts and
resolved on the client: the most recently edited version wins and the other
version's password is preserved in the item's password history, so a
conflict never silently loses a password. Deletions are tombstones.

## On the device

- **Profile** (`profile.json`): account record, encrypted keyset, encrypted
  vaults and items, encrypted sync token. Written atomically with
  owner-only permissions (`0600`), with one backup copy.
- **Device secrets** (`device.json`): the Secret Key. Kept separate so the
  profile can be backed up or synced by other means without the Secret Key.
- Web vault and extension: both live in the browser's IndexedDB for the
  vault (or extension) origin.
- Decrypted keys and items exist only in memory while unlocked and are wiped
  (zeroized) when the app locks. Rust's memory safety rules out whole classes
  of bugs (buffer overflows, use-after-free) in the crypto and parsing code.
- **Auto-lock** after inactivity (default 10 minutes).
- **Biometric unlock** (optional; macOS, iOS, Windows): the account key is
  stored encrypted with a random 256-bit device key that the operating
  system releases only after Touch ID, Face ID or Windows Hello. On iOS the
  device key is a keychain item that the Secure Enclave opens only for the
  currently enrolled face or fingers, on this device, while a passcode is
  set. On macOS Touch ID is checked through LocalAuthentication and the key
  sits in the login keychain, readable only by 2Secret. On Windows the
  device key is derived (HKDF) from a Windows Hello signature over a fixed
  challenge: the private key stays in the TPM and the device key is never
  stored. The master password is required again every 14 days, and turning
  the feature off or removing the account deletes the device key.
- **iOS AutoFill** (only while biometric unlock is on): the app shares the
  logins and passkeys AutoFill may fill with its extension through a file in
  the app group, encrypted with ChaCha20-Poly1305 under a new random key on
  every write. The key is a keychain item that opens only after Face ID or
  Touch ID with the current enrolment, on this device. The extension cannot
  change the vault and stops filling after the same 14 days. iOS receives
  websites, user names and passkey IDs for its suggestions, never passwords
  or keys. Details: [APP-STORE.md](APP-STORE.md#how-autofill-works).
- **Clipboard**: copied secrets are cleared after a configurable time
  (default 90 s) if the clipboard still contains them. Browsers only allow
  reading the clipboard after a permission prompt, so the web vault and the
  extension clear it without checking.
- **CLI sessions** (`eval "$(2secret unlock)"`) store the account key
  encrypted with a random key that lives only in the shell's environment
  variable, and expire after 30 minutes of inactivity.
- **Browser extension**: to avoid re-entering the master password every time
  the popup opens, the account key is kept in `chrome.storage.session` —
  browser memory that is only accessible to the extension and cleared when the
  browser closes — until the auto-lock time passes. Autofill injects a small
  self-contained function into the active tab only when you click *Fill*.
  Logins and one-time codes never pass through a content script. Right before filling, the tab's address and the address of every
  frame are checked again against the item's websites, so credentials never
  reach a frame from another site (an ad, a hostile embed) or a page the tab
  navigated to after the popup opened. Websites are matched by registrable
  domain using the Public Suffix List (`alice.github.io` never matches
  `mallory.github.io`), an `https` item is never filled into an `http` page,
  and an item URL with a port only matches that port.

## Master password and key derivation policy

- Master passwords need at least 12 characters and a "good" zxcvbn rating
  (name and e-mail address count against it).
- Argon2id parameters are stored per account so they can be raised later.
  Clients refuse to derive keys, and servers refuse to store accounts, with
  parameters below 19 MiB of memory and 2 passes, so a hostile or outdated
  server cannot talk a client into weak key derivation.
- Every encrypted JSON blob (items, vault names, keys, tokens) is padded with
  JSON whitespace to a size class before encryption: 256-byte steps up to
  4 KiB, 4 KiB steps up to 64 KiB, then 64 KiB steps.

## Lessons from the LastPass breaches

| What went wrong at LastPass | How 2Secret handles it |
|---|---|
| Stolen vault backups could be attacked offline; weak master passwords fell first | The Secret Key adds 130 random bits to every account: the server database alone is useless for guessing passwords |
| Website URLs were stored unencrypted, revealing which sites every user has | Titles, URLs, usernames, notes and vault names are all encrypted; item sizes are padded |
| Old accounts kept 1–5,000 PBKDF2 iterations for years | Argon2id (64 MiB, 3 passes) from day one, with an enforced minimum on client and server |
| Short master passwords (8 characters) were allowed | At least 12 characters and a "good" strength rating |
| Older vaults used AES-ECB/CBC without integrity protection | Authenticated encryption (XChaCha20-Poly1305) with every ciphertext bound to its place (associated data) |
| Browser extension bugs let web pages and iframes trigger fills or read data | Fill only on an explicit click, page and every frame re-checked against the item; pages can only ask for a passkey, which opens 2Secret for the user to decide |
| Access to the vault storage by a compromised engineer exposed everything | The server never holds a key that decrypts anything; self-hosters keep their own infrastructure |

## Web vault hardening

`2secret-server` serves the web vault with a strict Content-Security-Policy
(`script-src 'self' 'wasm-unsafe-eval'`, no inline scripts, no `eval`,
`frame-ancestors 'none'`), `X-Frame-Options: DENY`, `nosniff`,
`Referrer-Policy: no-referrer` and `Cache-Control: no-store`. The only
third-party connection allowed is the optional Have I Been Pwned range API.

## Exports

Encrypted backups use a password-only envelope: Argon2id (default parameters)
+ XChaCha20-Poly1305. Plain JSON/CSV exports contain secrets in clear text and
the apps warn about this.

## Known limitations

- Rotating a vault key uses the members' public keys as the server reports
  them; compare fingerprints in the member list (see *Fingerprints*).
- Metadata listed above (counts, size classes, timestamps, sharing graph,
  e-mail addresses) is visible to the server operator.
- Login uses TLS from the operating system or browser; whether that
  connection is quantum-resistant depends on the TLS stack and the reverse
  proxy in front of the server. The data inside it is end-to-end encrypted
  with 256-bit symmetric keys and the hybrid scheme above either way.
- The web vault is only as trustworthy as the server that serves its code. If
  you do not trust the server operator, use the desktop/mobile apps or the
  extension, whose code does not come from the server.
- 2Secret has not yet had an independent security audit. Reviews are very
  welcome.
