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
cp "$here/background.js" "$out/background.js"
cp "$here/fill.js" "$out/fill.js"
mkdir -p "$out/passkeys" && cp "$here"/passkeys/*.js "$out/passkeys/"
for s in 16 32 64 128; do cp "$root/crates/app/assets/icon-$s.png" "$out/icons/icon-$s.png"; done

# Extension pages may not load scripts from absolute "/./" paths in Firefox.
sed -i.bak 's#"/\./#"./#g' "$out/index.html" && rm -f "$out/index.html.bak"
# The popup shares the fill code with the background worker (fill.js), loaded
# before the app's own module.
grep -q 'src="./fill.js"' "$out/index.html" || {
  sed -i.bak 's#<script type="module"#<script src="./fill.js"></script><script type="module"#' "$out/index.html" && rm -f "$out/index.html.bak"
}
grep -q 'src="./fill.js"' "$out/index.html" || { echo "fill.js was not added to index.html" >&2; exit 1; }

cd "$out" && rm -f "$here/2secret-extension.zip" && zip -qr "$here/2secret-extension.zip" .
echo "Extension built in $out"
