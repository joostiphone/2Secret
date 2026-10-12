
## Downloads

| File | What |
|---|---|
| `*.dmg` | macOS app (Apple silicon) |
| `*.msi`, `*-setup.exe` | Windows app |
| `*.deb`, `*.rpm`, `*.AppImage` | Linux app (x86_64) |
| `2secret-*-<platform>.tar.gz` / `.zip` | `2secret` CLI and `2secret-server` for Linux, macOS (Apple silicon and Intel) and Windows |
| `2secret-web-*.tar.gz` | Web vault – serve it with `2secret-server --web-dir` |
| `2secret-extension-*.zip` | Browser extension for Chrome, Edge, Brave and Firefox (load unpacked) |
| `SHA256SUMS` | Checksums of all files |

Server image: `docker pull ghcr.io/joostiphone/2secret:latest` – see
[self-hosting](https://github.com/joostiphone/2Secret/blob/HEAD/docs/SELF-HOSTING.md).

The apps are not code-signed yet. On macOS, open the app the first time with
right-click → *Open* (or *System Settings → Privacy & Security → Open Anyway*).
On Windows, SmartScreen may ask you to confirm (*More info → Run anyway*).

FreeBSD, OpenBSD, NetBSD and iOS: build from source, see the
[README](https://github.com/joostiphone/2Secret#building-from-source).
