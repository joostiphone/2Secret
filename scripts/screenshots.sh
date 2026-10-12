#!/usr/bin/env bash
# Regenerates docs/screenshots (English and Dutch, light and dark, desktop
# and phone) and docs/screenshots/manifest.json, which the 2secret.app
# website imports.
#
#   scripts/screenshots.sh
#
# Needs: Rust, the Dioxus CLI (dx), Node.js with Playwright and Chromium,
# and optionally Python with Pillow to shrink the PNGs.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/docs/screenshots"
tmp="$(mktemp -d)"
port=8799
server="http://127.0.0.1:$port"
trap 'kill "$pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT

cd "$root"
cargo build -q -p twosecret-cli -p twosecret-server
(cd crates/app && dx bundle --platform web --release > "$tmp/dx.log" 2>&1) || { cat "$tmp/dx.log"; exit 1; }

./target/debug/2secret-server --bind "127.0.0.1:$port" --data-dir "$tmp/data" \
  --web-dir crates/app/dist/public --signups open > "$tmp/server.log" 2>&1 &
pid=$!
for _ in $(seq 50); do curl -sf "$server/api/v1/health" > /dev/null && break; sleep 0.2; done

export PATH="$root/target/debug:$PATH"
scripts/screenshots/seed.sh "$server" "$tmp/work" en
scripts/screenshots/seed.sh "$server" "$tmp/work" nl

rm -f "$out"/*.png "$out/manifest.json"
node scripts/screenshots/shoot.js "$server" "$tmp/work" "$out"

if python3 -c 'import PIL' 2> /dev/null; then
  python3 - "$out" <<'PY'
import sys, pathlib
from PIL import Image
for p in pathlib.Path(sys.argv[1]).glob('*.png'):
    Image.open(p).save(p, optimize=True)
PY
fi
echo "Screenshots written to docs/screenshots."
