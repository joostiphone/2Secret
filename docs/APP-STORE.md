# Publishing the iOS app

The App Store build is an Xcode project (`ios/project.yml`, generated with
XcodeGen) that links the Rust app as a static library and adds the AutoFill
extension. `scripts/ios-appstore.sh` builds, signs and uploads it; the
**Release** workflow runs it once the secrets below exist. Everything the
store listing needs is in `ios/AppStore`:

| Path | Contents |
|---|---|
| `ios/AppStore/metadata/<language>/` | Name, subtitle, description, keywords, promotional text, URLs and release notes in English and Dutch (the layout of fastlane *deliver*) |
| `ios/AppStore/screenshots/<language>/` | The screenshots to upload: iPhone 6.9" (1320 × 2868), iPhone 6.3" (1206 × 2622) and iPad 13" (2064 × 2752) |
| `ios/AppStore/design/` | Their design: `template.html` (layout), `slides.json` (captions), `screens/` (the app's screens) |
| `ios/AppStore/review/notes.txt` | Notes for App Review |
| `ios/AppStore/testflight/<language>.txt` | What is new and what to test in this build, for TestFlight testers; set on every build by the TestFlight workflow |
| `ios/App/PrivacyInfo.xcprivacy` | Privacy manifest: no tracking; the account data on the 2Secret server |

`scripts/screenshots.sh` takes the app's screens from the web vault with demo
data and renders the screenshots. After changing a caption or the design, run
only `node scripts/screenshots/appstore-compose.js`. Apple requires at least
one screenshot for a 6.3" iPhone and, because 2Secret runs on iPad, one for a
13" iPad; it scales them down for smaller screens.

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
`scripts/appstore.py signing` makes them with the API key below. It creates
one *Apple Distribution* certificate, whose private key is derived from the
API key so that every build reuses it, and new App Store profiles
(`2Secret-AppStore-CI`, `2Secret-AutoFill-AppStore-CI`) for every build.

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
  *Yes, we collect data*, because the 2Secret server (`sync.2secret.app`)
  keeps account data of the people who choose it: **Contact Info → Email
  Address** and **Name**, **Identifiers → User ID**, and **Other Data**
  (the names of signed-in devices); for each *App Functionality*, linked to
  the user, not used for tracking. Vault contents are end-to-end encrypted:
  the operator cannot access them, so they are not *collected* in Apple's
  sense. This matches the privacy manifest and the privacy policy.
- **Age Rating**: no in-app controls or capabilities (no web browser,
  user-generated content, chat or ads) and *None* for every content
  descriptor: 4+.
- **Digital Services Act** (*Business → Agreements → Compliance*): whether
  you are a *trader* in the EU sense. A trader's address, phone number and
  e-mail address are shown on the product page in the EU.
- **Version page**: set the version to the build's version number, copy
  the texts from `ios/AppStore/metadata`, upload the screenshots from
  `ios/AppStore/screenshots`, and paste `ios/AppStore/review/notes.txt` into
  *App Review Information → Notes*. Give App Review a demo account on
  `sync.2secret.app` with some items and a shared vault (user name: its
  e-mail address, password: its master password, the Secret Key in the
  notes): without one, sync and sharing cannot be reviewed.

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
Connect. To upload a version again without a new release, for example right
after adding the secrets, start *Actions → TestFlight → Run workflow* with
the version (`v1.3.0`). After Apple processes it (10–30 minutes) it appears in
**TestFlight**: try it there first, on a real iPhone and iPad, including:

- creating a local vault, syncing with your server, Face ID unlock;
- AutoFill: turn on Face ID unlock in 2Secret, enable 2Secret in iOS
  *Settings → General → AutoFill & Passwords*, fill a password in Safari and
  sign in with a passkey that was saved with the browser extension.

Then select the build on the version page and choose *Add for Review*.

To build on your own Mac instead: `brew install xcodegen`, set the four
variables above in your shell and run `scripts/ios-appstore.sh 1.9.1`
(the build number defaults to the date and time). Without the variables the
script only builds for the simulator. It uses a temporary keychain and
restores your keychain list afterwards.

### iPhone Duo and Xcode 27

iPhone Duo, the folding iPhone, gives an app its whole screen only when the
app is built with the iOS 27.1 SDK (Xcode 27.1). Built with an older SDK it
runs at a familiar iPhone size on the inner display, and on the outer display
to the left of the status bar and camera.

An app built with the iOS 27 SDK must use the UIScene life cycle, or it does
not start ([TN3187](https://developer.apple.com/documentation/technotes/tn3187-migrating-to-the-uikit-scene-based-life-cycle)).
2Secret's window comes from tao 0.34 through Dioxus 0.7, which does not use
it; tao 0.37, which Dioxus 0.8 uses, does. Until 2Secret moves to Dioxus 0.8,
the TestFlight workflow builds with Xcode 26 and `scripts/ios-appstore.sh`
refuses the iOS 27 SDK. Then:

1. update Dioxus and add `UIApplicationSceneManifest` to the app's
   `Info.plist` in `ios/project.yml`;
2. remove the Xcode 26 step from `.github/workflows/testflight.yml` and the
   SDK check from `scripts/ios-appstore.sh`;
3. try every pose (closed, open, partly folded, turned, split view) in the
   iPhone Duo simulator in Xcode's Device Hub.

The layout is ready for it: the safe areas apply on every side, a medium
width shows the list and the item side by side with the fold between them,
and a foldable that reports its fold (CSS Viewport Segments) gets the split
right at the fold.

## Export compliance

App Store Connect asks about encryption for every build until
`ITSAppUsesNonExemptEncryption` is set in the app's Info.plist. The answers
are the publisher's to give; the facts they need:

- 2Secret encrypts user data with standard, published algorithms
  (XChaCha20-Poly1305, Argon2id, HKDF-SHA-256, X25519, ML-KEM-768 / FIPS 203,
  ECDSA P-256), implemented in the app itself rather than only through iOS.
- Its source code, including the cryptography, is publicly available under
  the Apache 2.0 license.
- Encryption is the app's main purpose (protecting the user's own data), not
  only HTTPS.

Read Apple's *Complying with encryption export regulations* and answer the
questions in App Store Connect accordingly. For an industry standard
algorithm that does not come with the operating system, App Store Connect
asks for no documentation, except the French encryption declaration when the
app is distributed in France (*App Information → App Encryption
Documentation*); France controls secure storage apps such as password
managers. When in doubt, ask an export-control specialist.

App Store Connect classified 1.9.1 as not needing documentation, so the app's
`info.properties` in `ios/project.yml` set `ITSAppUsesNonExemptEncryption:
false` and App Store Connect no longer asks. If that changes, for example for
France, set it to `true` and add `ITSEncryptionExportComplianceCode` with the
code Apple gives after approving the documentation.

## How AutoFill works

The AutoFill extension runs outside the app and cannot unlock the vault
itself. While the app is unlocked and *Unlock with Face ID* is on, it writes
the logins, passkeys and one-time password secrets AutoFill may use to a file
in the app group, encrypted with ChaCha20-Poly1305 under a new random key on
every write. The key is kept in the keychain, shared through the app group,
readable only after Face ID or Touch ID with the current enrolment, on this
device. The extension stops filling after 14 days without the master
password, like the app. iOS also gets the websites, user names and passkey
IDs (never passwords, keys or one-time password secrets) for its suggestions
above the keyboard. Turning Face ID unlock off removes all of it. AutoFill
cannot save new passkeys; those are created with the browser extension and
sync to the phone.

From iOS 18 the extension also fills verification codes
(`ProvidesOneTimeCodes`), computed from the login's one-time password. The
app registers the `otpauth` URL scheme, so it can be chosen under *Settings →
General → AutoFill & Passwords → Set Up Codes In*: setup links and QR codes
then open 2Secret, which asks which login gets the one-time password.

The Mac works the same way (`macos/`, sharing `ios/AutoFill/Vault.swift`)
with *Unlock with Touch ID*: the app group is
`<Team ID>.io.github.joostiphone.twosecret` (on macOS app groups start with
the Team ID), the key is in the data protection keychain under that access
group, and the extension needs macOS 14 (verification codes macOS 15).
`scripts/macos-sign.sh` builds the extension into the Developer ID release
and registers the `otpauth` URL scheme in the app's Info.plist; see
CONTRIBUTING.md, *Signing the macOS app*.
