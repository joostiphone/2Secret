# Publishing the iOS app

The App Store build is an Xcode project (`ios/project.yml`, generated with
XcodeGen) that links the Rust app as a static library and adds the AutoFill
extension. `scripts/ios-appstore.sh` builds, signs and uploads it; the
**Release** workflow runs it once the secrets below exist. Everything the
store listing needs is in `ios/AppStore`:

| Path | Contents |
|---|---|
| `ios/AppStore/metadata/<language>/` | Name, subtitle, description, keywords, promotional text, URLs and release notes in English and Dutch (the layout of fastlane *deliver*) |
| `ios/AppStore/screenshots/<language>/` | iPhone 6.9" (1320 × 2868) and iPad 13" (2064 × 2752) screenshots, made by `scripts/screenshots.sh` |
| `ios/AppStore/review/notes.txt` | Notes for App Review |
| `ios/App/PrivacyInfo.xcprivacy` | Privacy manifest: no tracking, no data collected |

## 1. Apple Developer Program

Join at developer.apple.com/programs (99 USD per year). Note your **Team ID**
(*Account → Membership details*).

## 2. Identifiers

On developer.apple.com → *Certificates, Identifiers & Profiles*:

1. *Identifiers → +  → App Groups*: `group.io.github.joostiphone.twosecret`.
2. *Identifiers → + → App IDs → App*:
   - `io.github.joostiphone.twosecret` (2Secret) with the capabilities
     **App Groups** (select the group above) and **AutoFill Credential
     Provider**.
   - `io.github.joostiphone.twosecret.autofill` (2Secret AutoFill) with the
     same two capabilities.

Certificates and provisioning profiles do not have to be made by hand:
Xcode creates them with the API key below.

## 3. The app in App Store Connect

appstoreconnect.apple.com → *Apps → + → New App*: platform iOS, name
"2Secret Password Manager", primary language English (U.S.), bundle ID
`io.github.joostiphone.twosecret`, SKU e.g. `2secret`.

Then fill in:

- **App Information**: category *Productivity* (secondary *Utilities*), the
  Dutch localization, content rights (no third-party content).
- **Pricing and Availability**: the one-time price you want; 2Secret has no
  in-app purchases or subscriptions.
- **App Privacy**: privacy policy URL `https://2secret.app/privacy`, and
  *Data Not Collected*: vault data is end-to-end encrypted and only goes to
  the server the user chooses, the developer receives nothing.
- **Age Rating**: answer *None* everywhere (4+).
- **Version page**: copy the texts from `ios/AppStore/metadata`, upload the
  screenshots from `ios/AppStore/screenshots`, and paste
  `ios/AppStore/review/notes.txt` into *App Review Information → Notes*. App
  Review needs no demo account: a local vault works without a server.

## 4. API key and repository secrets

App Store Connect → *Users and Access → Integrations → App Store Connect
API → Team Keys → +*, access **Admin** (needed to create the distribution
certificate). Download the `.p8` file (possible only once) and note the
*Key ID* and the *Issuer ID* above the list.

Add these repository secrets (*Settings → Secrets and variables →
Actions*):

| Secret | Value |
|---|---|
| `APPLE_TEAM_ID` | Your Team ID (already there if you set up macOS signing) |
| `APP_STORE_CONNECT_KEY_ID` | The key's ID |
| `APP_STORE_CONNECT_ISSUER_ID` | The issuer ID |
| `APP_STORE_CONNECT_KEY` | The full contents of the `.p8` file |

## 5. Building and submitting

Every release (*Actions → Release*) now uploads the iOS app to App Store
Connect. After Apple processes it (10–30 minutes) it appears in
**TestFlight**: try it there first, on a real iPhone and iPad, including:

- creating a local vault, syncing with your server, Face ID unlock;
- AutoFill: turn on Face ID unlock in 2Secret, enable 2Secret in iOS
  *Settings → General → AutoFill & Passwords*, fill a password in Safari and
  sign in with a passkey that was saved with the browser extension.

Then select the build on the version page and choose *Add for Review*.

To build on your own Mac instead: `brew install xcodegen`, set the four
variables above in your shell and run `scripts/ios-appstore.sh 1.2.0 42`
(version, build number). Without the variables the script only builds for
the simulator.

## Export compliance (your decision)

App Store Connect asks about encryption for every build until
`ITSAppUsesNonExemptEncryption` is set in the app's Info.plist, which this
project deliberately leaves to you. The facts you need:

- 2Secret encrypts user data with standard, published algorithms
  (XChaCha20-Poly1305, Argon2id, HKDF-SHA-256, X25519, ML-KEM-768 / FIPS 203,
  ECDSA P-256), implemented in the app itself rather than only through iOS.
- Its source code, including the cryptography, is publicly available under
  the Apache 2.0 license.
- Encryption is the app's main purpose (protecting the user's own data), not
  only HTTPS.

Read Apple's *Complying with encryption export regulations* and answer the
questions in App Store Connect accordingly; for distribution in France an
import declaration may be required. When in doubt, ask an export-control
specialist. Once settled, add your answer to `ios/project.yml` under the
app's `info.properties` (`ITSAppUsesNonExemptEncryption: false` or `true`
with your compliance code) so App Store Connect stops asking.

## How AutoFill works

The AutoFill extension runs outside the app and cannot unlock the vault
itself. While the app is unlocked and *Unlock with Face ID* is on, it writes
the logins and passkeys AutoFill may use to a file in the app group,
encrypted with ChaCha20-Poly1305 under a new random key on every write. The
key is kept in the keychain, shared through the app group, readable only
after Face ID or Touch ID with the current enrolment, on this device. The
extension stops filling after 14 days without the master password, like the
app. iOS also gets the websites, user names and passkey IDs (never
passwords or keys) for its suggestions above the keyboard. Turning Face ID
unlock off removes all of it. AutoFill cannot save new passkeys; those are
created with the browser extension and sync to the phone.
