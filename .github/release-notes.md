
## Downloads

| File | What |
|---|---|
| `2Secret_*_aarch64.dmg` | macOS app for Apple silicon (M1 and newer) |
| `2Secret_*_x64.dmg` | macOS app for Intel Macs |
| `2Secret_*_x64-setup.exe` | Windows app (installs for your user and can update itself; removes an `.msi` version of 2Secret up to 1.7.0) |
| `*.deb`, `*.rpm`, `*.AppImage` | Linux app (x86_64) |
| `2Secret_*_android-arm64.apk` | Android app (Android 7 and newer) – allow installing from your browser when asked |
| `2Secret_*_android-arm64.aab` | Android app bundle for app stores |
| `2secret-*-<platform>.tar.gz` / `.zip` | `2secret` CLI and `2secret-server` for Linux, macOS (Apple silicon and Intel) and Windows |
| `2secret-web-*.tar.gz` | Web vault – serve it with `2secret-server --web-dir` |
| `2secret-extension-*.zip` | Browser extension for Chrome, Edge, Brave and Firefox (load unpacked) |
| `SHA256SUMS` | Checksums of all files |

Server image for x86_64 and ARM64 (e.g. Raspberry Pi 4/5 with a 64-bit OS):
`docker pull ghcr.io/joostiphone/2secret:latest` – see
[self-hosting](https://github.com/joostiphone/2Secret/blob/HEAD/docs/SELF-HOSTING.md).

On macOS, drag 2Secret to *Applications* and open it. If macOS says it cannot
verify the app, open *System Settings → Privacy & Security* and click *Open
Anyway* (on macOS 14 and older you can also right-click the app and choose
*Open*).
On Windows, SmartScreen may ask you to confirm (*More info → Run anyway*).

FreeBSD, OpenBSD, NetBSD and iOS: build from source, see the
[README](https://github.com/joostiphone/2Secret#building-from-source).
