# Updates

The desktop and Android apps can look for new versions themselves. This is
**off by default**: nothing is checked until you click *Check now* or turn
on automatic updates (*Settings → Updates*). Checking contacts GitHub, where
2Secret is published, once a day; no account or vault data is sent.

## What happens per platform

| Installed as | With automatic updates on |
|---|---|
| Windows, with `2Secret_<version>_x64-setup.exe` (the default per-user installation) | The new setup is downloaded and verified. The next time 2Secret starts (or right away with *Restart now*), it quits, the setup runs silently and 2Secret starts again. |
| macOS, `2Secret.app` in a folder you may write to (`/Applications` for administrators) | The new disk image is downloaded and verified. At the next start (or *Restart now*) its app replaces the current one, after `codesign --verify`, and is started. |
| Linux AppImage | The new AppImage is downloaded and verified, and replaces the old file at the next start (or *Restart now*). |
| Windows `.msi` in *Program Files* (releases up to 1.7.0) | The app says a new version is available and *Download* gets the setup, which offers to remove the `.msi` version, so one 2Secret is left. |
| macOS app in a read-only place, Linux `.deb` / `.rpm`, the BSDs | The app says a new version is available and *Download* opens it; install it as usual (or with your package manager). |
| Android | The app says a new version is available and *Download* opens the new `.apk`; Android asks you to confirm the installation. |
| iOS, web vault, browser extension | Updated by the App Store, your server and the browser's extension store; no updater in the app. |

If an installation at start does not finish (for example because the setup
was stopped), 2Secret does not try it again at every start: it says so under
*Settings → Updates*, and you can download the version yourself.

## Security

An update could replace everything that protects your vault, so the apps
install nothing on the word of the network alone:

- Every release has an `update.json` with the version, the release page and,
  per platform, the installer's URL, size and SHA-256, and an
  `update.json.sig`: an **Ed25519 signature** over the exact bytes of
  `update.json`.
- The apps contain the public key(s) that may sign updates
  (`crates/core/src/update_keys.txt`). A manifest with any other signature, or
  none, is rejected.
- The installer must come from that version's GitHub release
  (`https://github.com/joostiphone/2Secret/releases/download/v<version>/`) and
  match the signed size and SHA-256 exactly. Downloads are size-limited and
  HTTPS-only.
- Only **newer** versions are installed, so an old but validly signed
  manifest cannot downgrade the app to a version with known problems.
- A downloaded update is kept in a folder only you can read and is verified
  again, signature included, right before it is installed.

This protects against tampered downloads, mirrors, interception of the
connection and a release asset replaced afterwards. Because installers are
only accepted from this repository's releases over HTTPS, the private key
alone is not enough to push an update either. Someone who can run the
Release workflow, or who has the private key, can sign an update; keep the
`UPDATE_SIGNING_KEY` secret and the repository's write access to people you
trust, and require two-factor authentication on GitHub.

## Checking a download

Downloads that do not update themselves (`.deb`, `.rpm`, the browser
extension, the CLI and server archives) can be checked by hand. Every
release has `SHA256SUMS`, signed with the same Ed25519 key as `update.json`
into `SHA256SUMS.sig`. With OpenSSL 3, in the folder with the downloads:

```sh
# The public key from crates/core/src/update_keys.txt, as a PEM file.
{ printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'
  printf '%s' szLMLOdfhjWs5oMdLfeXR23tZEpjEjn1D+lJFRDBWFY= | openssl base64 -d -A; } > 2secret.der
openssl base64 -d -A -in SHA256SUMS.sig > SHA256SUMS.bin
openssl pkeyutl -verify -pubin -keyform DER -inkey 2secret.der -rawin \
  -in SHA256SUMS -sigfile SHA256SUMS.bin          # "Signature Verified Successfully"
sha256sum --check --ignore-missing SHA256SUMS     # every file you downloaded: OK
```

Releases up to 1.9.1 have no `SHA256SUMS.sig`.

## For maintainers: the signing key

The **Release** workflow writes `update.json`
(`scripts/update-manifest.py`) and signs it with the private key in the
repository secret `UPDATE_SIGNING_KEY` (`scripts/sign-update.sh`), then
checks the signature against `update_keys.txt` so a release is never signed
with a key the apps reject. Without the secret the release has no
`update.json` and the apps do not offer it as an update (the workflow shows a
warning).

Set it up once: *Settings → Secrets and variables → Actions → New repository
secret*, name `UPDATE_SIGNING_KEY`, value the complete PEM file including the
`-----BEGIN PRIVATE KEY-----` and `-----END PRIVATE KEY-----` lines. Keep an
offline backup of the key (for example in 2Secret itself) and delete other
copies.

### A new key

To make a key (OpenSSL 3; on macOS `brew install openssl@3`):

```sh
openssl genpkey -algorithm ed25519 -out 2secret-update-signing-key.pem
openssl pkey -in 2secret-update-signing-key.pem -pubout -outform DER | tail -c 32 | base64
```

The second command prints the public key. Before the first release with the
updater, replacing the key in `update_keys.txt` is enough. Later, installed
apps only trust the keys they were built with, so change keys in two steps:

1. Add the new public key to `update_keys.txt` (keep the old one) and release
   a version still signed with the **old** key.
2. Once people have that version, put the new private key in
   `UPDATE_SIGNING_KEY`, and remove the old public key from
   `update_keys.txt` in a later release.

If the private key leaks, remove its public key from `update_keys.txt` and
release a version signed with a new key straight away; apps that are still
older will not update automatically to it and need a manual download once.
