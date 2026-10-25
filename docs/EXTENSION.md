# The browser extension

The 2Secret extension (Chrome, Chromium, Brave, Microsoft Edge, Vivaldi, Arc,
Firefox) is the web vault packaged as a popup, plus a background script for
passkeys and for the connection to the desktop app that lets AI agents sign
in without seeing a password ([AGENTS.md](AGENTS.md), *Filling a login in
your browser*).

## Building

```sh
./extension/build.sh      # extension/dist/ and extension/2secret-extension.zip
```

`build.sh` bundles the Dioxus web app with the `extension` feature, then adds
`manifest.json`, `background.js`, `fill.js` (the fill code shared by the popup
and the background) and `passkeys/`. Load `extension/dist` as an unpacked
extension (`chrome://extensions`, *Developer mode*, *Load unpacked*) or as a
temporary add-on in Firefox (`about:debugging`). Every release carries the
zip as `2secret-extension.zip`.

Tests (need Playwright with Chromium and a display, `xvfb-run` on a server):

```sh
xvfb-run -a node extension/tests/passkeys.js   # passkeys from a page through 2Secret
xvfb-run -a node extension/tests/fill.js       # a login from the app, filled and submitted
```

## Ids

- **Chromium browsers** derive an extension's id from the public key in its
  manifest. `manifest.json` carries 2Secret's key, so the store build and an
  unpacked build of this repository share the id
  `gnkfgnlegljjfnihdefkjepdoaphccfd`. The desktop app allows that id in the
  native messaging host manifests it writes (`KNOWN_EXTENSION_IDS` in
  `crates/agent/src/native_host.rs`; a test checks that the key gives that
  id). A build without the key, or with another key, gets another id: enter
  it in the app under *Browser connection → Extension ids of development
  builds*.
- **Firefox** uses the id from the manifest:
  `2secret@joostiphone.github.io`.

The private key that belongs to the manifest's public key is not needed to
build or publish anything (the stores sign the packages themselves); it only
matters for packing a `.crx` by hand.

## The connection to the desktop app

The extension connects to the app through
[native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging):
the browser starts the program named in a small manifest and talks to it on
its stdin and stdout. For 2Secret that program is the desktop app itself,
which recognises the browser's arguments and runs the host loop instead of
opening a window (`crates/agent/src/host.rs`, `crates/app/src/native_host.rs`).
The host connects to the app's Agent Access socket as a *browser*, waits for
the logins the user allows an agent to use, hands each to the extension and
reports the outcome. The app writes the manifests with one button
(*Settings → Desktop app → Browser connection*); where they go per browser and
operating system is listed in [AGENTS.md](AGENTS.md).

Frames between the extension and the host (4 bytes little-endian length,
then JSON):

```
extension → host   {"type":"hello","extension":"1.11.0","browser":"chrome"}
host → extension   {"type":"status","app":true,"version":"1.11.0"}
host → extension   {"type":"ping"}                                   every 20 s
host → extension   {"type":"fill","id":"f-7","url":"https://github.com/login",
                    "rules":[{"domain":"github.com","https":true,"port":null,"exact":false}],
                    "username":"octo","password":"…","code":"123456","submit":true}
extension → host   {"type":"fill_result","id":"f-7","outcome":"filled","submitted":true}
```

`outcome` is `filled`, `nothing` (a matching tab, but no field to fill) or
`no_tab` (no active tab that belongs to the item's website). The extension
fills the active tab of the window used last, then any other window's active
tab, the first whose address the item's rules allow; never a background tab,
never incognito. The pings keep the extension's service worker alive; when
the port drops, the extension reconnects after a growing pause, and a
watchdog alarm reconnects after the browser or the worker restarted.

## Publishing

### Chrome Web Store

1. Register as a developer at the [Chrome Web Store developer dashboard](https://chrome.google.com/webstore/devconsole)
   (one-off fee).
2. *New item*, upload `extension/2secret-extension.zip`. The manifest's `key`
   keeps the id `gnkfgnlegljjfnihdefkjepdoaphccfd`; check it on the item's
   page after the upload. Should the store assign another id, copy the
   public key the dashboard shows under *Package → View public key* into
   `manifest.json` and the new id into `KNOWN_EXTENSION_IDS`, and release
   again.
3. Fill in the listing from `extension/store/listing-en.md` (and the Dutch
   text from `listing-nl.md` as a second language), the screenshots from the
   website, and the privacy answers from `extension/store/privacy.md`. The
   permission `nativeMessaging` needs a justification: the text is in
   `privacy.md`.
4. Submit for review. Updates: upload the new zip from the release.

### Firefox Add-ons (addons.mozilla.org)

1. Create an account at [addons.mozilla.org](https://addons.mozilla.org/developers/)
   (free).
2. *Submit a New Add-on*, *On this site*, upload the zip; the source code is
   this repository (give the tag). Firefox needs the `.xpi` signed by
   Mozilla, which the review produces; an unsigned build only loads as a
   temporary add-on.
3. Listing texts and privacy answers as above.
4. Later releases can be signed from the release workflow with `web-ext sign`
   and the AMO API credentials as repository secrets.

### Edge Add-ons

Microsoft Edge installs extensions from the Chrome Web Store (after the user
allows it), so a separate listing is optional. The same zip works in the
[Partner Center](https://partner.microsoft.com/dashboard/microsoftedge).
