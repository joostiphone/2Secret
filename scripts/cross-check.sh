#!/usr/bin/env bash
# Lints the apps for macOS, iOS, Windows and Android from any machine, so
# platform-specific code (Touch ID, Face ID, Windows Hello, ...) is checked
# without a Mac or a Windows PC. This only type-checks; real builds need the
# platform's SDK (see CI).
#
#   pip install ziglang && scripts/cross-check.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tools="$(mktemp -d)"
trap 'rm -rf "$tools"' EXIT
cc() { # name zig-target
  printf '#!/bin/sh\nexec python3 "%s/scripts/zig/cc.py" %s "$@"\n' "$root" "$2" > "$tools/$1"
  chmod +x "$tools/$1"
}
cc apple aarch64-macos
cc android aarch64-linux-musl
cc windows x86_64-windows-gnu
printf '#!/bin/sh\nexec python3 -m ziglang lib "$@"\n' > "$tools/lib" && chmod +x "$tools/lib"
mkdir -p "$tools/sdk"

export SDKROOT="$tools/sdk"
export CC_aarch64_apple_darwin="$tools/apple" CC_aarch64_apple_ios="$tools/apple"
export CC_aarch64_linux_android="$tools/android"
export CC_x86_64_pc_windows_msvc="$tools/windows" AR_x86_64_pc_windows_msvc="$tools/lib"

cd "$root"
rustup target add aarch64-apple-darwin aarch64-apple-ios aarch64-linux-android x86_64-pc-windows-msvc > /dev/null 2>&1
for args in \
  "--target aarch64-apple-darwin" \
  "--target x86_64-pc-windows-msvc" \
  "--target aarch64-apple-ios --no-default-features --features mobile" \
  "--target aarch64-linux-android --no-default-features --features mobile"; do
  echo "== twosecret-app $args"
  # shellcheck disable=SC2086
  cargo clippy -q -p twosecret-app $args -- -D warnings
done
echo "All platforms pass."
