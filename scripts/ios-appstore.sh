#!/usr/bin/env bash
# Builds the iOS app with its AutoFill extension and uploads it to App Store
# Connect (TestFlight / App Store). Runs on macOS with Xcode.
#
#   scripts/ios-appstore.sh [version] [build number]
#
# Needs Rust, XcodeGen (`brew install xcodegen`) and, to sign and upload, an
# App Store Connect API key with the Admin role:
#   APPLE_TEAM_ID                 10-character Team ID
#   APP_STORE_CONNECT_KEY_ID      the key's ID
#   APP_STORE_CONNECT_ISSUER_ID   the issuer ID shown above the keys
#   APP_STORE_CONNECT_KEY         the contents of AuthKey_<id>.p8
# `scripts/appstore.py signing` then provides the distribution certificate and
# the provisioning profiles; the bundle IDs and the app group must exist
# (docs/APP-STORE.md). Without the key the app is only built for the
# simulator, which checks that everything compiles.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
version="${1:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)}"
version="${version#v}"
# Build numbers must go up for every upload of a version.
build="${2:-$(date -u +%Y%m%d.%H%M)}"

# iPhone Duo gives an app its whole screen only when it is built with the
# iOS 27.1 SDK (Xcode 27.1); see docs/APP-STORE.md.
sdk="$(xcrun --sdk iphoneos --show-sdk-version 2> /dev/null || echo 0)"
if [ "$(printf '%s\n' 27.1 "$sdk" | sort -V | head -1)" != 27.1 ]; then
  echo "warning: built with the iOS $sdk SDK; iPhone Duo shows the app at iPhone size (Xcode 27.1 or later fixes that)" >&2
fi

if [ -n "${APP_STORE_CONNECT_KEY:-}" ]; then
  target=aarch64-apple-ios profile=release
else
  target=aarch64-apple-ios-sim profile=debug
fi
cd "$root"
rustup target add "$target" > /dev/null
# The system libraries the Rust code needs; rustc only prints them when it
# compiles the crate, hence the touch.
touch crates/app/src/lib.rs
flags=(-p twosecret-app --lib --crate-type staticlib --target "$target" --no-default-features --features mobile)
[ "$profile" = release ] && flags+=(--release)
libs="$(cargo rustc --color never "${flags[@]}" -- --print native-static-libs 2>&1 | tee /dev/stderr \
  | sed -n 's/.*native-static-libs: //p' | tail -1 | sed $'s/\x1b\\[[0-9;]*m//g')"
[ -f "target/$target/$profile/libtwosecret_app.a" ] || { echo "libtwosecret_app.a was not built" >&2; exit 1; }

cd ios
xcodegen generate --quiet
settings=(
  RUST_LIB_DIR="$root/target/$target/$profile"
  RUST_NATIVE_LIBS="$libs"
  MARKETING_VERSION="$version"
  CURRENT_PROJECT_VERSION="$build"
)

if [ "$profile" = debug ]; then
  # scripts/ios-simulator-check.sh starts this build.
  xcodebuild build -project TwoSecret.xcodeproj -scheme 2Secret -configuration Debug \
    -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' ARCHS=arm64 \
    -derivedDataPath build/DerivedData CODE_SIGNING_ALLOWED=NO "${settings[@]}"
  echo "Built for the simulator (no App Store Connect key, nothing uploaded)."
  exit 0
fi

rm -rf build && mkdir -p build
signing="$PWD/build/signing"
key="$PWD/build/AuthKey.p8"
keychain="$signing/signing.keychain-db"
old_keychains="$(security list-keychains -d user | tr -d '"')"
cleanup() {
  # shellcheck disable=SC2086
  security list-keychains -d user -s $old_keychains
  security delete-keychain "$keychain" 2> /dev/null || true
  rm -rf "$key" "$signing"
}
trap cleanup EXIT
printf '%s\n' "$APP_STORE_CONNECT_KEY" > "$key"

# Certificate and profiles from the App Store Connect API.
python3 -c 'import cryptography' 2> /dev/null || {
  python3 -m venv build/venv && build/venv/bin/pip install --quiet cryptography && PATH="$PWD/build/venv/bin:$PATH"
}
python3 "$root/scripts/appstore.py" signing "$signing"
# shellcheck disable=SC1091
. "$signing/signing.env"

# A temporary keychain with the certificate (and Apple's intermediate).
keychain_password="$(openssl rand -hex 16)"
security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
curl -fsSL -o "$signing/AppleWWDRCAG3.cer" https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer &&
  security import "$signing/AppleWWDRCAG3.cer" -k "$keychain" > /dev/null || true
security import "$signing/distribution.p12" -k "$keychain" -P "$P12_PASSWORD" -T /usr/bin/codesign -T /usr/bin/security
security set-key-partition-list -S apple-tool:,apple: -s -k "$keychain_password" "$keychain" > /dev/null
# shellcheck disable=SC2086
security list-keychains -d user -s "$keychain" $old_keychains
for dir in "$HOME/Library/MobileDevice/Provisioning Profiles" "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"; do
  mkdir -p "$dir"
  cp "$signing/app.mobileprovision" "$dir/$APP_PROFILE_UUID.mobileprovision"
  cp "$signing/autofill.mobileprovision" "$dir/$AUTOFILL_PROFILE_UUID.mobileprovision"
done

xcodebuild archive -project TwoSecret.xcodeproj -scheme 2Secret -configuration Release \
  -destination 'generic/platform=iOS' -archivePath build/2Secret.xcarchive \
  DEVELOPMENT_TEAM="$APPLE_TEAM_ID" CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY="Apple Distribution" \
  APP_PROFILE="$APP_PROFILE" AUTOFILL_PROFILE="$AUTOFILL_PROFILE" OTHER_CODE_SIGN_FLAGS="--keychain $keychain" \
  "${settings[@]}"
cat > build/ExportOptions.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>method</key><string>app-store-connect</string>
  <key>destination</key><string>upload</string>
  <key>teamID</key><string>$APPLE_TEAM_ID</string>
  <key>signingStyle</key><string>manual</string>
  <key>signingCertificate</key><string>Apple Distribution</string>
  <key>provisioningProfiles</key>
  <dict>
    <key>io.github.joostiphone.twosecret</key><string>$APP_PROFILE</string>
    <key>io.github.joostiphone.twosecret.autofill</key><string>$AUTOFILL_PROFILE</string>
  </dict>
  <key>manageAppVersionAndBuildNumber</key><false/>
</dict>
</plist>
PLIST
# The upload signs in with the API key.
xcodebuild -exportArchive -archivePath build/2Secret.xcarchive \
  -exportOptionsPlist build/ExportOptions.plist -exportPath build/export \
  -authenticationKeyPath "$key" -authenticationKeyID "$APP_STORE_CONNECT_KEY_ID" \
  -authenticationKeyIssuerID "$APP_STORE_CONNECT_ISSUER_ID"
echo "Uploaded 2Secret $version ($build) to App Store Connect; it appears in TestFlight after processing."
