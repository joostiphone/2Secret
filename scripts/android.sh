#!/usr/bin/env bash
# Builds the Android app for phones and tablets (arm64).
#
#   scripts/android.sh [version] [output dir]
#
# Needs the Android SDK and NDK (ANDROID_HOME, ANDROID_NDK_HOME), Java 17 and
# the Dioxus CLI (dx). To sign a release, set
#   ANDROID_KEYSTORE_BASE64    the keystore (.jks), base64 encoded
#   ANDROID_KEYSTORE_PASSWORD  its password
#   ANDROID_KEY_ALIAS          the key's alias
#   ANDROID_KEY_PASSWORD       the key's password
# (letters and digits only). Signed builds produce an .apk to install
# directly and an .aab for Google Play. Without a key the result is a debug
# build, which is only meant for testing: Android lets anyone with USB access
# read a debug app's files.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
version="${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)}"
version="${version#v}"
out="${2:-$root/dist/android}"
IFS=. read -r major minor patch <<< "$version"
# dx always writes versionCode 1; Android needs it to grow with every release.
code=$((major * 10000 + minor * 100 + ${patch%%[!0-9]*}))

app="$root/crates/app"
keystore="$root/.android-release.jks"
cp "$app/Dioxus.toml" "$app/Dioxus.toml.orig"
cleanup() { mv "$app/Dioxus.toml.orig" "$app/Dioxus.toml"; rm -f "$keystore"; }
trap cleanup EXIT

signed=0
if [ -n "${ANDROID_KEYSTORE_BASE64:-}" ]; then
  printf '%s' "$ANDROID_KEYSTORE_BASE64" | base64 -d > "$keystore"
  # dx resolves jks_file relative to the directory that holds target/.
  cat >> "$app/Dioxus.toml" <<TOML

[bundle.android]
jks_file = ".android-release.jks"
jks_password = "$ANDROID_KEYSTORE_PASSWORD"
key_alias = "$ANDROID_KEY_ALIAS"
key_password = "$ANDROID_KEY_PASSWORD"
TOML
  signed=1
fi

(cd "$app" && dx bundle --platform android --release --target aarch64-linux-android --package-types apk)

gradle="$(find "$root/target/dx" -path '*/release/android/app/app/build.gradle.kts' | head -1)"
project="$(dirname "$(dirname "$gradle")")"
sed -i.bak "s/versionCode = 1\$/versionCode = $code/" "$gradle" && rm -f "$gradle.bak"
grep -q "versionCode = $code" "$gradle"
if [ "$signed" = 1 ]; then
  (cd "$project" && ./gradlew --quiet assembleRelease bundleRelease)
else
  (cd "$project" && ./gradlew --quiet assembleDebug)
fi

mkdir -p "$out"
if [ "$signed" = 1 ]; then
  cp "$project/app/build/outputs/apk/release/app-release.apk" "$out/2Secret_${version}_android-arm64.apk"
  cp "$project/app/build/outputs/bundle/release/app-release.aab" "$out/2Secret_${version}_android-arm64.aab"
else
  cp "$project/app/build/outputs/apk/debug/app-debug.apk" "$out/2Secret_${version}_android-arm64-debug.apk"
fi
ls -l "$out"
