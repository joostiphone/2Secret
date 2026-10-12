#!/usr/bin/env sh
# Build the 2Secret browser extension (Chrome, Edge, Brave, Firefox).
#
#   ./extension/build.sh            -> extension/dist/ and extension/2secret-extension.zip
#
# Load extension/dist as an unpacked extension (chrome://extensions, "Developer
# mode") or as a temporary add-on in Firefox (about:debugging).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"

cd "$root/crates/app"
# dx keeps old hashed bundles around; start clean.
rm -rf dist "$root"/target/dx/*/release/web
dx bundle --platform web --release --no-default-features --features extension

out="$here/dist"
rm -rf "$out"
mkdir -p "$out/icons"
cp -R "$root/crates/app/dist/public/." "$out/"
cp "$here/manifest.json" "$out/manifest.json"
for s in 16 32 64 128; do cp "$root/crates/app/assets/icon-$s.png" "$out/icons/icon-$s.png"; done

# Extension pages may not load scripts from absolute "/./" paths in Firefox.
sed -i.bak 's#"/\./#"./#g' "$out/index.html" && rm -f "$out/index.html.bak"

cd "$out" && rm -f "$here/2secret-extension.zip" && zip -qr "$here/2secret-extension.zip" .
echo "Extension built in $out"
