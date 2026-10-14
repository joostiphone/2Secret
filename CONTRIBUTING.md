# Contributing to 2Secret

Thanks for helping! Bug reports, translations, reviews of the security design
and pull requests are all welcome.

## Development setup

```sh
rustup toolchain install stable
rustup target add wasm32-unknown-unknown
cargo install dioxus-cli --version 0.7.10 --locked   # or: cargo binstall dioxus-cli@0.7.10

# Linux only, for the desktop app:
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libxdo-dev libayatana-appindicator3-dev librsvg2-dev
```

## Checks before opening a pull request

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The client crate contains end-to-end tests that start a real server and run
the complete crypto; the CLI crate runs the real binary.

## Guidelines

- Keep `twosecret-core` free of I/O and platform code so it keeps working on
  every target (including WebAssembly).
- Never log or print secrets. Wrap new secret types so they are zeroized on
  drop and redacted in `Debug` output.
- Changes to cryptography or the sync protocol need tests and an update of
  [docs/SECURITY.md](docs/SECURITY.md) or [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- UI text goes through `i18n::t("key")`; add English and Dutch strings to
  `crates/app/src/i18n.rs` (a test fails when a key is missing).

## Translations

Adding a language means adding a variant to `Lang` and a column to the table
in `crates/app/src/i18n.rs`.

By contributing you agree that your contributions are licensed under the MIT
or Apache-2.0 license, at the user's option.

## Other platforms

`scripts/cross-check.sh` lints the apps for macOS, iOS, Windows and Android
from any machine (`pip install ziglang` first), so code for Touch ID, Face
ID or Windows Hello is checked without a Mac or a Windows PC.

## Screenshots

`scripts/screenshots.sh` regenerates `docs/screenshots`: English and Dutch,
light and dark, desktop and phone, from demo data on a temporary local server.
It also writes `docs/screenshots/manifest.json`, which the 2secret.app website
imports. It needs Node.js with Playwright and Chromium. Run it after visible
UI changes and commit the result.

## Releasing

1. Update the version in `Cargo.toml` and add a section to `CHANGELOG.md`.
2. Start the **Release** workflow from the Actions tab (*Run workflow*, enter
   e.g. `v1.2.3`) or push a tag `v1.2.3`.
3. The workflow builds all installers and the Docker image and publishes the
   release with all downloads attached. Versions with a suffix (`v1.3.0-beta.1`)
   become pre-releases.

### Signing updates

The apps only update to releases with a signed `update.json`, which the
workflow makes when the repository secret `UPDATE_SIGNING_KEY` holds the
Ed25519 private key (PEM) belonging to a public key in
`crates/core/src/update_keys.txt`. See [docs/UPDATES.md](docs/UPDATES.md) for
setting it up and changing keys.

### Signing the macOS app

Without further setup the macOS app is signed ad hoc, and people have to allow
it once under *System Settings → Privacy & Security*. With an Apple Developer
Program membership the release workflow (`scripts/macos-sign.sh`) signs it
with your Developer ID, adds the AutoFill extension (Safari and other apps
fill from 2Secret, see `macos/`) and has Apple notarize it, so it opens
without warnings. Add these repository secrets (*Settings → Secrets and
variables → Actions*):

| Secret | Value |
|---|---|
| `APPLE_CERTIFICATE` | Your *Developer ID Application* certificate with its private key, exported from Keychain Access as `.p12` and base64 encoded (`base64 -i certificate.p12 \| pbcopy`) |
| `APPLE_CERTIFICATE_PASSWORD` | The password you chose when exporting the `.p12` |
| `APPLE_TEAM_ID` | Your 10-character Team ID (developer.apple.com → *Account → Membership details*) |

Create the certificate on a Mac in Xcode (*Settings → Accounts → Manage
Certificates → + → Developer ID Application*) or on developer.apple.com.
Only the Account Holder can; Apple does not let API keys create one.

The App Store Connect API key of the iOS build (`APP_STORE_CONNECT_KEY`,
`APP_STORE_CONNECT_KEY_ID`, `APP_STORE_CONNECT_ISSUER_ID`, see
[docs/APP-STORE.md](docs/APP-STORE.md)) is used too: `scripts/appstore.py
developer-id` makes Developer ID provisioning profiles for
`io.github.joostiphone.twosecret` and `.autofill` (named
`2Secret-DeveloperID-CI` and `2Secret-AutoFill-DeveloperID-CI`), which allow
the AutoFill entitlement, and the key notarizes. Without the key the app is
signed without AutoFill and only notarized with these two secrets:

| Secret | Value |
|---|---|
| `APPLE_ID` | The Apple ID of the developer account |
| `APPLE_PASSWORD` | An app-specific password for that Apple ID (account.apple.com → *Sign-In and Security*) |

Apple can take days to notarize the first submissions of a new team. The
release waits at most 20 minutes for the app, then publishes it signed but
not stapled; macOS finds the ticket online once Apple has accepted it, and
until then asks to allow the app once under *Privacy & Security*.

### Signing the Android app

Releases include the Android app only when a signing key is configured
(debug builds can be read over USB and are never published). Create a key
once and **keep a backup**: updates must be signed with the same key, or
Android refuses to install them over the existing app.

```sh
keytool -genkeypair -v -keystore 2secret-release.jks -keyalg RSA -keysize 4096 \
  -validity 10000 -alias 2secret
base64 -w0 2secret-release.jks    # macOS: base64 -i 2secret-release.jks
```

Use letters and digits only for the passwords, then add these repository
secrets:

| Secret | Value |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | The base64 output above |
| `ANDROID_KEYSTORE_PASSWORD` | The keystore password |
| `ANDROID_KEY_ALIAS` | `2secret` (the `-alias` above) |
| `ANDROID_KEY_PASSWORD` | The key password |

The release then gets `2Secret_<version>_android-arm64.apk` (install
directly) and `.aab` (for Google Play, where this key becomes the upload
key). Build locally with `scripts/android.sh` and the same environment
variables.
